rule sig_20161207_4f18e833964340ccc47588508064bb39 {
  meta:
    description = "datamaliciousorder - file 20161207_4f18e833964340ccc47588508064bb39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2949398891f7327fefa892f2e0c623a11f4954b7d60c4adf6a02f981d3ad2e3e"

  strings:
    $s1 = "= new Date();vYq2[\"setUTCFullYear\"](\"2003\");if (vYq2.getUTCFullYear().toString(10) == \"2003\") {var vLc2 = vDUa0.split(\"##" ascii
    $s2 = "var vDj7 = new Function(\"vDUa0\", '{return vDUa0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCj7 = new Function(\"vDUa" ascii
    $s3 = "eturn vLc2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vDj7 = new Function(\"vDUa0\", '{return vDUa0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCj7 = new Function(\"vDUa" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}