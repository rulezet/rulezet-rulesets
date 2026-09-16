rule TTP_XOR_QUAD_CurrentVersionRun_c742 {
  strings:
    $key_c742 = { 94 2d [2] b0 23 [2] 9b 0f [2] b5 2d [2] a1 36 [2] ae 2c [2] b0 31 [2] b2 30 [2] a9 36 [2] b5 31 [2] a9 1e }

  condition:
    any of them
}