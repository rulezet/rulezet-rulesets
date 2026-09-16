rule sig_20161207_4b5d8895582460223e530d7e05865b84 {
  meta:
    description = "datamaliciousorder - file 20161207_4b5d8895582460223e530d7e05865b84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1829225cf3b4b695468866ef4fe00a47638d51dc3df95072a5b70b4fed659807"

  strings:
    $s1 = "var vYv6 = new Function(\"vGx1\", '{var vSm7 = new Date();vSm7[\"setUTCFullYear\"](\"2003\");if (vSm7.getUTCFullYear().toString(" ascii
    $s2 = "var vYv6 = new Function(\"vGx1\", '{var vSm7 = new Date();vSm7[\"setUTCFullYear\"](\"2003\");if (vSm7.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vHEg4 = vGx1.split(\"###\"); return vHEg4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vKAy5 = new Function(\"vGx1\", '{return vGx1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}