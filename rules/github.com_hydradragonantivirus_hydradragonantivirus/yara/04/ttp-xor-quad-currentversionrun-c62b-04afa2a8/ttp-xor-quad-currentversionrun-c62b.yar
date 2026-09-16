rule TTP_XOR_QUAD_CurrentVersionRun_c62b {
  strings:
    $key_c62b = { 95 44 [2] b1 4a [2] 9a 66 [2] b4 44 [2] a0 5f [2] af 45 [2] b1 58 [2] b3 59 [2] a8 5f [2] b4 58 [2] a8 77 }

  condition:
    any of them
}