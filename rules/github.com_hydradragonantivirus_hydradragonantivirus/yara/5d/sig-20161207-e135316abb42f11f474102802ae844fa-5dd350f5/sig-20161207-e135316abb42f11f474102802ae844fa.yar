rule sig_20161207_e135316abb42f11f474102802ae844fa {
  meta:
    description = "datamaliciousorder - file 20161207_e135316abb42f11f474102802ae844fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a13b5dcc6eb6cf98b80e7eee74b3f851a378b4f53ef581784517ca74025d9b4d"

  strings:
    $s1 = "var vLVx6 = new Function(\"vKn4\", '{return vKn4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEBl2 = new Function(\"vKn4" ascii
    $s2 = "= new Date();vLOn2[\"setUTCFullYear\"](\"2003\");if (vLOn2.getUTCFullYear().toString(10) == \"2003\") {var vEFy1 = vKn4.split(\"" ascii
    $s3 = " return vEFy1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vLVx6 = new Function(\"vKn4\", '{return vKn4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEBl2 = new Function(\"vKn4" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}