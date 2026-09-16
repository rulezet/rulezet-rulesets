rule TTP_XOR_QUAD_CurrentVersionRun_c173 {
  strings:
    $key_c173 = { 92 1c [2] b6 12 [2] 9d 3e [2] b3 1c [2] a7 07 [2] a8 1d [2] b6 00 [2] b4 01 [2] af 07 [2] b3 00 [2] af 2f }

  condition:
    any of them
}