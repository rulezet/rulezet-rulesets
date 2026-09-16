rule TTP_XOR_QUAD_CurrentVersionRun_bcdc {
  strings:
    $key_bcdc = { ef b3 [2] cb bd [2] e0 91 [2] ce b3 [2] da a8 [2] d5 b2 [2] cb af [2] c9 ae [2] d2 a8 [2] ce af [2] d2 80 }

  condition:
    any of them
}