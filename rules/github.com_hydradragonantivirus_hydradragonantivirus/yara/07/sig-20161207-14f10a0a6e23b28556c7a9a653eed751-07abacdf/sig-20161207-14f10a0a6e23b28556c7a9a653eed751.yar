rule sig_20161207_14f10a0a6e23b28556c7a9a653eed751 {
  meta:
    description = "datamaliciousorder - file 20161207_14f10a0a6e23b28556c7a9a653eed751.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e474e2b649a8326b19d587f4b4cdeee8991d1c8dc178625052b2cad4d370349b"

  strings:
    $s1 = "var vJBf9 = new Function(\"vJy8\", '{var vQb8 = new Date();vQb8[\"setUTCFullYear\"](\"2003\");if (vQb8.getUTCFullYear().toString" ascii
    $s2 = "var vJBf9 = new Function(\"vJy8\", '{var vQb8 = new Date();vQb8[\"setUTCFullYear\"](\"2003\");if (vQb8.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vMAa8 = vJy8.split(\"###\"); return vMAa8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vVi8 = new Function(\"vJy8\", '{return vJy8.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}