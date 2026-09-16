rule sig_20161207_f0dfb487f03ebf5fdaaacad9a159009d {
  meta:
    description = "datamaliciousorder - file 20161207_f0dfb487f03ebf5fdaaacad9a159009d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3dd047fba240e954ca06164406a65919cff7e521a16a7fbc80b007eeb4dc6d8"

  strings:
    $s1 = "var vXs2 = new Function(\"vCBf4\", '{var vGx1 = new Date();vGx1[\"setUTCFullYear\"](\"2003\");if (vGx1.getUTCFullYear().toString" ascii
    $s2 = "var vXs2 = new Function(\"vCBf4\", '{var vGx1 = new Date();vGx1[\"setUTCFullYear\"](\"2003\");if (vGx1.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vQs9 = vCBf4.split(\"###\"); return vQs9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vUf7 = new Function(\"vCBf4\", '{return vCBf4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}