rule sig_20161207_49afbea16a795bcad8beb42e4054c9c8 {
  meta:
    description = "datamaliciousorder - file 20161207_49afbea16a795bcad8beb42e4054c9c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b402623b28d91a66921a1966a52a8272e708b710045b9fbb144f5a02edb1e44"

  strings:
    $s1 = "var vZx9 = new Function(\"vCi3\", '{var vCOq6 = new Date();vCOq6[\"setUTCFullYear\"](\"2003\");if (vCOq6.getUTCFullYear().toStri" ascii
    $s2 = "var vZx9 = new Function(\"vCi3\", '{var vCOq6 = new Date();vCOq6[\"setUTCFullYear\"](\"2003\");if (vCOq6.getUTCFullYear().toStri" ascii
    $s3 = "var vNIj7 = new Function(\"vCi3\", '{return vCi3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vVf2 = vCi3.split(\"###\"); return vVf2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}