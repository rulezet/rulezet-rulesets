rule sig_20161206_a4dfd02ee2dbf95d67ceca145d9ce221 {
  meta:
    description = "datamaliciousorder - file 20161206_a4dfd02ee2dbf95d67ceca145d9ce221.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90406ee6c870b07e0040697a625348cd75547ef040676a2bd0dc81188f5e28ca"

  strings:
    $s1 = "var vIp1 = new Function(\"s\", '{var vZRs3 = new Date();vZRs3[\"setUTCFullYear\"](\"2003\");if (vZRs3.getUTCFullYear().toString(" ascii
    $s2 = "var vIp1 = new Function(\"s\", '{var vZRs3 = new Date();vZRs3[\"setUTCFullYear\"](\"2003\");if (vZRs3.getUTCFullYear().toString(" ascii
    $s3 = "function vEEt7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vXQz6 = s.split(\"##\"); return vXQz6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}