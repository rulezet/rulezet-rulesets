rule sig_20161207_773931890a0039bf04b4bdfa66c40955 {
  meta:
    description = "datamaliciousorder - file 20161207_773931890a0039bf04b4bdfa66c40955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b22cc461eabd5d4d843fa0df43e342b0fc3cb3a5b2827978f346b00faf1ff25b"

  strings:
    $s1 = "var vXJc8 = new Function(\"vIa1\", '{var vWl2 = new Date();vWl2[\"setUTCFullYear\"](\"2003\");if (vWl2.getUTCFullYear().toString" ascii
    $s2 = "var vXJc8 = new Function(\"vIa1\", '{var vWl2 = new Date();vWl2[\"setUTCFullYear\"](\"2003\");if (vWl2.getUTCFullYear().toString" ascii
    $s3 = "var vTu0 = new Function(\"vIa1\", '{return vIa1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vZFn3 = vIa1.split(\"###\"); return vZFn3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}