rule sig_20161207_832a675cd8bdbaf836f688801e892b80 {
  meta:
    description = "datamaliciousorder - file 20161207_832a675cd8bdbaf836f688801e892b80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1848c457f249be0da8849adff5754b8223a09b5257fe457f77f601c8ce19baa"

  strings:
    $s1 = "var vWTl3 = new Function(\"vEz8\", '{var vNXa7 = new Date();vNXa7[\"setUTCFullYear\"](\"2003\");if (vNXa7.getUTCFullYear().toStr" ascii
    $s2 = "var vWTl3 = new Function(\"vEz8\", '{var vNXa7 = new Date();vNXa7[\"setUTCFullYear\"](\"2003\");if (vNXa7.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vMBs3 = vEz8.split(\"###\"); return vMBs3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vCd6 = new Function(\"vEz8\", '{return vEz8.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}