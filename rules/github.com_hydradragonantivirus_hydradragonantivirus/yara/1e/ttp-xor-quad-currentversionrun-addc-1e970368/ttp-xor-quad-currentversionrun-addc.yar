rule TTP_XOR_QUAD_CurrentVersionRun_addc {
  strings:
    $key_addc = { fe b3 [2] da bd [2] f1 91 [2] df b3 [2] cb a8 [2] c4 b2 [2] da af [2] d8 ae [2] c3 a8 [2] df af [2] c3 80 }

  condition:
    any of them
}