rule sig_20161208_ad8450065797c5a4497296a931bfd837 {
  meta:
    description = "datamaliciousorder - file 20161208_ad8450065797c5a4497296a931bfd837.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab25f71f96e3c13a79cdfa3402fbfb053f189a4f6a3bb1612219e1b057ece6fb"

  strings:
    $s1 = "var vZd9 = new Function(\"vCYb9\", '{return vCYb9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWb6 = new Function(\"vCYb" ascii
    $s2 = "= new Date();vPn4[\"setUTC\"+\"FullYear\"](\"2003\");if (vPn4.getUTCFullYear().toString(10) == \"2003\") {var vBRb0 = vCYb9.spli" ascii
    $s3 = "); return vBRb0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vZd9 = new Function(\"vCYb9\", '{return vCYb9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWb6 = new Function(\"vCYb" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}