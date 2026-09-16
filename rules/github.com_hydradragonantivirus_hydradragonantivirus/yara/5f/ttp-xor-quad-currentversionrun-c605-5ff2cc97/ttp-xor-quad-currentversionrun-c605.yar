rule TTP_XOR_QUAD_CurrentVersionRun_c605 {
  strings:
    $key_c605 = { 95 6a [2] b1 64 [2] 9a 48 [2] b4 6a [2] a0 71 [2] af 6b [2] b1 76 [2] b3 77 [2] a8 71 [2] b4 76 [2] a8 59 }

  condition:
    any of them
}