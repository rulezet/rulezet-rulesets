rule sig_20161207_d4e9840576c65739042bea616d215a88 {
  meta:
    description = "datamaliciousorder - file 20161207_d4e9840576c65739042bea616d215a88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d7022a0d5b81f6b9a1bc897cfecff094d91237b2dc6312bbcde618c017efbec"

  strings:
    $s1 = "7 = new Date();vJSd7[\"setUTCFullYear\"](\"2003\");if (vJSd7.getUTCFullYear().toString(10) == \"2003\") {var vAa0 = vYOy9.split(" ascii
    $s2 = "var vUIi8 = new Function(\"vYOy9\", '{return vYOy9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPv4 = new Function(\"vYO" ascii
    $s3 = "); return vAa0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUIi8 = new Function(\"vYOy9\", '{return vYOy9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPv4 = new Function(\"vYO" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}