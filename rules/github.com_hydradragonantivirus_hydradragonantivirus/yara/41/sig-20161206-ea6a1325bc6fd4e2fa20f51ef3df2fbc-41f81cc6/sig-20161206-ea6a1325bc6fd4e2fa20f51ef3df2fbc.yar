rule sig_20161206_ea6a1325bc6fd4e2fa20f51ef3df2fbc {
  meta:
    description = "datamaliciousorder - file 20161206_ea6a1325bc6fd4e2fa20f51ef3df2fbc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d235113f534b775231c16aac39c3a7a1d425546e30836576422b8c7c616cf3de"

  strings:
    $s1 = "var vMQc2 = new Function(\"s\", '{var vSk2 = new Date();vSk2[\"setUTCFullYear\"](\"2003\");if (vSk2.getUTCFullYear().toString(10" ascii
    $s2 = "var vMQc2 = new Function(\"s\", '{var vSk2 = new Date();vSk2[\"setUTCFullYear\"](\"2003\");if (vSk2.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vVs2 = s.split(\"##\"); return vVs2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vUUd5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}