rule sig_20161207_e871fbd95c53855e325eae577ac7074f {
  meta:
    description = "datamaliciousorder - file 20161207_e871fbd95c53855e325eae577ac7074f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a60a91166b472318f721ce665ec6cd4743739469dcdd4b7bdef20eb218771ff"

  strings:
    $s1 = "var vUOz1 = new Function(\"vKLu4\", '{var vMZm4 = new Date();vMZm4[\"setUTCFullYear\"](\"2003\");if (vMZm4.getUTCFullYear().toSt" ascii
    $s2 = "var vUOz1 = new Function(\"vKLu4\", '{var vMZm4 = new Date();vMZm4[\"setUTCFullYear\"](\"2003\");if (vMZm4.getUTCFullYear().toSt" ascii
    $s3 = "var vIy4 = new Function(\"vKLu4\", '{return vKLu4.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "0) == \"2003\") {var vNd0 = vKLu4.split(\"###\"); return vNd0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}