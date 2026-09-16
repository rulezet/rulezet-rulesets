rule _20160518_6ba4b930d5eb8f5e5627c8b86fa43192_20160518_9d9a1f9b4411_1305 {
  meta:
    description = "datamaliciousorder - from files 20160518_6ba4b930d5eb8f5e5627c8b86fa43192.js, 20160518_9d9a1f9b441144b56a20e65b4a31cb03.js, 20160518_ab6738062a89b2d80b5d2de19aee00c5.js, 20160518_ae1754d4195ab7496317cb2caa09a82b.js, 20160518_c7734d1c76b3a62e11f7230354f1e8e0.js, 20160518_f528a59f00d291815ebf498e2b82dccf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "769de800663224058c81d8e6cf4a91c8f9e6596afb6cf91650c30c393e84dd31"
    hash2       = "57ba4634ab2e3e999a5021ebccdf3b883ebcf0357ae175463fa85f2cdb41b6b2"
    hash3       = "d154b83d3f6969727899a3fdee5d4d41dd0aba384550ecbaa2ac0e0ad2e5bab0"
    hash4       = "34c2842c18e12f5885ec272cb90bd5a94bfd57453ccf9c8d5c354698635f68e2"
    hash5       = "e450f01acd3f1d5dafdd1271e734d878c91b11bb626fb9e32b4bfeca86ac3287"
    hash6       = "3d2d3711e85d340e0c919742ea59ad388d1ea1780aed1327f316e7c51f598aff"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* U  */, dingy, (true, false));" fullword ascii
    $s2 = "dot1 /* U  */= true;/* U  */" fullword ascii
    $s3 = "newtonsCradle1 /* U  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* U  */;};" fullword ascii
    $s5 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* U  */, A8name /* U  *" ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}