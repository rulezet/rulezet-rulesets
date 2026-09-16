rule sig_20161207_757d815ed9eb412b65964b765e371859 {
  meta:
    description = "datamaliciousorder - file 20161207_757d815ed9eb412b65964b765e371859.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfc8882ef0f82c5ac754dd8c69886d157641e0d636cc4ef9c1260a5920cc3840"

  strings:
    $s1 = "var vXEa2 = new Function(\"vWAt4\", '{var vNn0 = new Date();vNn0[\"setUTCFullYear\"](\"2003\");if (vNn0.getUTCFullYear().toStrin" ascii
    $s2 = "var vXEa2 = new Function(\"vWAt4\", '{var vNn0 = new Date();vNn0[\"setUTCFullYear\"](\"2003\");if (vNn0.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vEZh6 = vWAt4.split(\"###\"); return vEZh6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vRCd9 = new Function(\"vWAt4\", '{return vWAt4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}