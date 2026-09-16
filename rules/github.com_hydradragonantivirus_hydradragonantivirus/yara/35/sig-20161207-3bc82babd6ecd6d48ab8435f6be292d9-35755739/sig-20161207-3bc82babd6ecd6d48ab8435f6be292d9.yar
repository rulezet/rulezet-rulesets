rule sig_20161207_3bc82babd6ecd6d48ab8435f6be292d9 {
  meta:
    description = "datamaliciousorder - file 20161207_3bc82babd6ecd6d48ab8435f6be292d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fda7169ca027a691324e8a677fe067432f507242956ebdbbe380737f09d67e2"

  strings:
    $s1 = "var vVm4 = new Function(\"vNn0\", '{var vLu3 = new Date();vLu3[\"setUTCFullYear\"](\"2003\");if (vLu3.getUTCFullYear().toString(" ascii
    $s2 = "var vVm4 = new Function(\"vNn0\", '{var vLu3 = new Date();vLu3[\"setUTCFullYear\"](\"2003\");if (vLu3.getUTCFullYear().toString(" ascii
    $s3 = "var vHa1 = new Function(\"vNn0\", '{return vNn0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vBn6 = vNn0.split(\"###\"); return vBn6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}