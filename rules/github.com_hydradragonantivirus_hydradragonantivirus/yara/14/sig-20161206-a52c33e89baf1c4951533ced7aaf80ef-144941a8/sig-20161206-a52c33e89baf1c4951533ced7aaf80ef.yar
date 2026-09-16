rule sig_20161206_a52c33e89baf1c4951533ced7aaf80ef {
  meta:
    description = "datamaliciousorder - file 20161206_a52c33e89baf1c4951533ced7aaf80ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "def49c0db48613328ea9c1900253005e04b4f99f06c79ce61c5ffa94a0d6fef2"

  strings:
    $s1 = "var vNAm8 = new Function(\"s\", '{var vBj4 = new Date();vBj4[\"setUTCFullYear\"](\"2003\");if (vBj4.getUTCFullYear().toString(10" ascii
    $s2 = "var vNAm8 = new Function(\"s\", '{var vBj4 = new Date();vBj4[\"setUTCFullYear\"](\"2003\");if (vBj4.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vZu4 = s.split(\"##\"); return vZu4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vMCw7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}