rule sig_20161207_eea768243f2351a6d089cd0be723f720 {
  meta:
    description = "datamaliciousorder - file 20161207_eea768243f2351a6d089cd0be723f720.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aaf106f9c3eace1cf8252b9d07919a98bb2b3e1455bafb380420ec3152a3cf00"

  strings:
    $s1 = " = new Date();vDr7[\"setUTCFullYear\"](\"2003\");if (vDr7.getUTCFullYear().toString(10) == \"2003\") {var vRd0 = vABj2.split(\"#" ascii
    $s2 = "var vEt0 = new Function(\"vABj2\", '{return vABj2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAAe3 = new Function(\"vAB" ascii
    $s3 = "var vEt0 = new Function(\"vABj2\", '{return vABj2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAAe3 = new Function(\"vAB" ascii
    $s4 = "return vRd0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}