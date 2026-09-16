rule sig_20161207_cf8d63d08ac47b4b794cef58996fe922 {
  meta:
    description = "datamaliciousorder - file 20161207_cf8d63d08ac47b4b794cef58996fe922.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ce6ca9386f06fa1c635079f27477f9c0c9c5f44204cdbc375ec185c9e766734"

  strings:
    $s1 = "var vTy1 = new Function(\"vOVx3\", '{var vEMu0 = new Date();vEMu0[\"setUTCFullYear\"](\"2003\");if (vEMu0.getUTCFullYear().toStr" ascii
    $s2 = "var vTy1 = new Function(\"vOVx3\", '{var vEMu0 = new Date();vEMu0[\"setUTCFullYear\"](\"2003\");if (vEMu0.getUTCFullYear().toStr" ascii
    $s3 = "var vUt0 = new Function(\"vOVx3\", '{return vOVx3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vQHr7 = vOVx3.split(\"###\"); return vQHr7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}