rule TTP_XOR_QUAD_CurrentVersionRun_dad3 {
  strings:
    $key_dad3 = { 89 bc [2] ad b2 [2] 86 9e [2] a8 bc [2] bc a7 [2] b3 bd [2] ad a0 [2] af a1 [2] b4 a7 [2] a8 a0 [2] b4 8f }

  condition:
    any of them
}