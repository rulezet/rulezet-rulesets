rule sig_20161207_759cb1360531260dd08ff5c18a7580b1 {
  meta:
    description = "datamaliciousorder - file 20161207_759cb1360531260dd08ff5c18a7580b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75172dc75f2624cb56593d050e989c2c1d9cb33eb9a452a55a2b1fa1a8922fd0"

  strings:
    $s1 = "var vXj4 = new Function(\"vXQk2\", '{var vMSm3 = new Date();vMSm3[\"setUTCFullYear\"](\"2003\");if (vMSm3.getUTCFullYear().toStr" ascii
    $s2 = "var vXj4 = new Function(\"vXQk2\", '{var vMSm3 = new Date();vMSm3[\"setUTCFullYear\"](\"2003\");if (vMSm3.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vWMg3 = vXQk2.split(\"###\"); return vWMg3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vVOs5 = new Function(\"vXQk2\", '{return vXQk2.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}