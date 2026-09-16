rule TTP_XOR_QUAD_CurrentVersionRun_c668 {
  strings:
    $key_c668 = { 95 07 [2] b1 09 [2] 9a 25 [2] b4 07 [2] a0 1c [2] af 06 [2] b1 1b [2] b3 1a [2] a8 1c [2] b4 1b [2] a8 34 }

  condition:
    any of them
}