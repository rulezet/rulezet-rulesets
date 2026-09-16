rule sig_20161207_abe6bbebfe4c04cfe85d3fe6ed9aa0c2 {
  meta:
    description = "datamaliciousorder - file 20161207_abe6bbebfe4c04cfe85d3fe6ed9aa0c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "579739066b9339342f8028b2bedad5d5393df3427d1d1e2096efeffa031d03f8"

  strings:
    $s1 = "var vRy6 = new Function(\"vYb8\", '{var vGm6 = new Date();vGm6[\"setUTCFullYear\"](\"2003\");if (vGm6.getUTCFullYear().toString(" ascii
    $s2 = "var vRy6 = new Function(\"vYb8\", '{var vGm6 = new Date();vGm6[\"setUTCFullYear\"](\"2003\");if (vGm6.getUTCFullYear().toString(" ascii
    $s3 = "var vTZa0 = new Function(\"vYb8\", '{return vYb8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vNs6 = vYb8.split(\"###\"); return vNs6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}