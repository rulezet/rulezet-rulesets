rule sig_20161207_54c242d7cd140df92f7ecc9769236780 {
  meta:
    description = "datamaliciousorder - file 20161207_54c242d7cd140df92f7ecc9769236780.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74a4fbf18b80facdb0412552ab3a257fce9df04337046d8a849db8492efe969c"

  strings:
    $s1 = "var vGm8 = new Function(\"vTSt1\", '{var vHa3 = new Date();vHa3[\"setUTCFullYear\"](\"2003\");if (vHa3.getUTCFullYear().toString" ascii
    $s2 = "var vGm8 = new Function(\"vTSt1\", '{var vHa3 = new Date();vHa3[\"setUTCFullYear\"](\"2003\");if (vHa3.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vEj7 = vTSt1.split(\"###\"); return vEj7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vZi4 = new Function(\"vTSt1\", '{return vTSt1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}