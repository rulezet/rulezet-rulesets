rule sig_20161207_92136568de85abcce3670a7555c0ad57 {
  meta:
    description = "datamaliciousorder - file 20161207_92136568de85abcce3670a7555c0ad57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ef9821bf59f9e047d1fb5204d39cfa1c94509daecb392650c3c6eb83967c474"

  strings:
    $s1 = " = new Date();vCx5[\"setUTCFullYear\"](\"2003\");if (vCx5.getUTCFullYear().toString(10) == \"2003\") {var vMy7 = vNNr4.split(\"#" ascii
    $s2 = "var vIi7 = new Function(\"vNNr4\", '{return vNNr4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFWd5 = new Function(\"vNN" ascii
    $s3 = "var vIi7 = new Function(\"vNNr4\", '{return vNNr4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFWd5 = new Function(\"vNN" ascii
    $s4 = "return vMy7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}