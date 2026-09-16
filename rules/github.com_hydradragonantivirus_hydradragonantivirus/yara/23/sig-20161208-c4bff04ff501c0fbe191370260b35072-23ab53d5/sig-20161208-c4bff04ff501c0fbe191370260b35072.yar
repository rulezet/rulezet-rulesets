rule sig_20161208_c4bff04ff501c0fbe191370260b35072 {
  meta:
    description = "datamaliciousorder - file 20161208_c4bff04ff501c0fbe191370260b35072.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "662d95a8e5e70dddfeaa61c836f75089204771e17dfbd14ddcad5ed5d401b319"

  strings:
    $s1 = "var vFWi6 = new Function(\"vAe1\", '{return vAe1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCh1 = new Function(\"vAe1" ascii
    $s2 = "new Date();vTn0[\"setUTC\"+\"FullYear\"](\"2003\");if (vTn0.getUTCFullYear().toString(10) == \"2003\") {var vFp7 = vAe1.split(\"" ascii
    $s3 = "eturn vFp7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vFWi6 = new Function(\"vAe1\", '{return vAe1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCh1 = new Function(\"vAe1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}