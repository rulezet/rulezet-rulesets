rule sig_20161207_91fed6507e32efadbb7998fc16c7d9bc {
  meta:
    description = "datamaliciousorder - file 20161207_91fed6507e32efadbb7998fc16c7d9bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "157ce22978ab8ee83e8fcf95a7c5f29cbabd885ddd3315d8bd1ea914d402a551"

  strings:
    $s1 = "var vUt9 = new Function(\"vZk5\", '{return vZk5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYo7 = new Function(\"vZk5\"" ascii
    $s2 = "ew Date();vOi6[\"setUTCFullYear\"](\"2003\");if (vOi6.getUTCFullYear().toString(10) == \"2003\") {var vIm0 = vZk5.split(\"####\"" ascii
    $s3 = "n vIm0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUt9 = new Function(\"vZk5\", '{return vZk5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYo7 = new Function(\"vZk5\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}