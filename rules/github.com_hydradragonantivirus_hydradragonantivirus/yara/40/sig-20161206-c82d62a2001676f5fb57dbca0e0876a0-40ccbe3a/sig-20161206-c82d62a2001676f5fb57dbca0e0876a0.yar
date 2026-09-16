rule sig_20161206_c82d62a2001676f5fb57dbca0e0876a0 {
  meta:
    description = "datamaliciousorder - file 20161206_c82d62a2001676f5fb57dbca0e0876a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d20ac607b901f140b900310aad272f28f8fabebf81b0efbc6b472a2cbde125f"

  strings:
    $s1 = "var vCWr6 = new Function(\"s\", '{var vAYk2 = new Date();vAYk2[\"setUTCFullYear\"](\"2003\");if (vAYk2.getUTCFullYear().toString" ascii
    $s2 = "var vCWr6 = new Function(\"s\", '{var vAYk2 = new Date();vAYk2[\"setUTCFullYear\"](\"2003\");if (vAYk2.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vNLc8 = s.split(\"##\"); return vNLc8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vYd7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}