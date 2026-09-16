rule sig_20161207_03e963f335635cfb71a5a3cfe0a349ce {
  meta:
    description = "datamaliciousorder - file 20161207_03e963f335635cfb71a5a3cfe0a349ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a74a4d16eccc04a9e5904b50bbd186f3bbace13ee6ed23b02ac9c66b61f0df4f"

  strings:
    $s1 = "var vAm6 = new Function(\"vLEs8\", '{return vLEs8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJOu8 = new Function(\"vLE" ascii
    $s2 = "6 = new Date();vPLz6[\"setUTCFullYear\"](\"2003\");if (vPLz6.getUTCFullYear().toString(10) == \"2003\") {var vUn3 = vLEs8.split(" ascii
    $s3 = "); return vUn3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vAm6 = new Function(\"vLEs8\", '{return vLEs8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJOu8 = new Function(\"vLE" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}