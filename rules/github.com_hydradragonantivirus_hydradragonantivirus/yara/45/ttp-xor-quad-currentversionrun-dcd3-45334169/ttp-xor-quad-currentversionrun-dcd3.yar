rule TTP_XOR_QUAD_CurrentVersionRun_dcd3 {
  strings:
    $key_dcd3 = { 8f bc [2] ab b2 [2] 80 9e [2] ae bc [2] ba a7 [2] b5 bd [2] ab a0 [2] a9 a1 [2] b2 a7 [2] ae a0 [2] b2 8f }

  condition:
    any of them
}