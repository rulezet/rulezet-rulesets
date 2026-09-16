rule sig_20161207_b5bbad88c0a185d344ebce39838c9661 {
  meta:
    description = "datamaliciousorder - file 20161207_b5bbad88c0a185d344ebce39838c9661.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bbc2d975fa6d0ed9c468d10c9375cb59bde914cb9e392db4b1e8b715e717a8d"

  strings:
    $s1 = "var vCZf9 = new Function(\"vYd5\", '{var vPd4 = new Date();vPd4[\"setUTCFullYear\"](\"2003\");if (vPd4.getUTCFullYear().toString" ascii
    $s2 = "var vCZf9 = new Function(\"vYd5\", '{var vPd4 = new Date();vPd4[\"setUTCFullYear\"](\"2003\");if (vPd4.getUTCFullYear().toString" ascii
    $s3 = "var vGCn8 = new Function(\"vYd5\", '{return vYd5.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vFHw9 = vYd5.split(\"###\"); return vFHw9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}