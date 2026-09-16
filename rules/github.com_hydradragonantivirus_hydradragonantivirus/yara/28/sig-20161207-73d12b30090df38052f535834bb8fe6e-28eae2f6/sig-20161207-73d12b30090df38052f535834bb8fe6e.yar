rule sig_20161207_73d12b30090df38052f535834bb8fe6e {
  meta:
    description = "datamaliciousorder - file 20161207_73d12b30090df38052f535834bb8fe6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c90d0308115ad724f73ec6e54334d856575bcd73549d81e0d0d034df8b1d80"

  strings:
    $s1 = "var vNEf0 = new Function(\"vTBb9\", '{var vPi6 = new Date();vPi6[\"setUTCFullYear\"](\"2003\");if (vPi6.getUTCFullYear().toStrin" ascii
    $s2 = "var vNEf0 = new Function(\"vTBb9\", '{var vPi6 = new Date();vPi6[\"setUTCFullYear\"](\"2003\");if (vPi6.getUTCFullYear().toStrin" ascii
    $s3 = "var vEMd7 = new Function(\"vTBb9\", '{return vTBb9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vZJk9 = vTBb9.split(\"###\"); return vZJk9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}