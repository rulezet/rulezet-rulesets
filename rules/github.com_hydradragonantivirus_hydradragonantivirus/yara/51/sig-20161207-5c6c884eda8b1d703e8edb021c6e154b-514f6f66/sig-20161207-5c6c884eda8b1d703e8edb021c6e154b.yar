rule sig_20161207_5c6c884eda8b1d703e8edb021c6e154b {
  meta:
    description = "datamaliciousorder - file 20161207_5c6c884eda8b1d703e8edb021c6e154b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c3fd3c080895110d0eaeada09eee824d4dedb08d939d14bb0136386530a0755"

  strings:
    $s1 = "= new Date();vDu3[\"setUTCFullYear\"](\"2003\");if (vDu3.getUTCFullYear().toString(10) == \"2003\") {var vRv0 = vGLt4.split(\"##" ascii
    $s2 = "var vNd6 = new Function(\"vGLt4\", '{return vGLt4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBj9 = new Function(\"vGLt" ascii
    $s3 = "eturn vRv0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNd6 = new Function(\"vGLt4\", '{return vGLt4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBj9 = new Function(\"vGLt" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}