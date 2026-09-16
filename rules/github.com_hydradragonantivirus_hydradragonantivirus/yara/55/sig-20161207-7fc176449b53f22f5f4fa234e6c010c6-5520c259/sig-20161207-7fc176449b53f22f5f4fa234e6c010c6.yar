rule sig_20161207_7fc176449b53f22f5f4fa234e6c010c6 {
  meta:
    description = "datamaliciousorder - file 20161207_7fc176449b53f22f5f4fa234e6c010c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee022a457a093e76424c3e4b95b2dc0bd95e538ee903cdef79068e34fc1d6336"

  strings:
    $s1 = "var vBXt3 = new Function(\"vOw1\", '{return vOw1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEEt6 = new Function(\"vOw1" ascii
    $s2 = "= new Date();vTSp4[\"setUTCFullYear\"](\"2003\");if (vTSp4.getUTCFullYear().toString(10) == \"2003\") {var vUHr5 = vOw1.split(\"" ascii
    $s3 = " return vUHr5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vBXt3 = new Function(\"vOw1\", '{return vOw1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEEt6 = new Function(\"vOw1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}