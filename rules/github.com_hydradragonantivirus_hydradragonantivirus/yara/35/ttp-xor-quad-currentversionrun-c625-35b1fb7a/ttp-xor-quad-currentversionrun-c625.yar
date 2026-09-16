rule TTP_XOR_QUAD_CurrentVersionRun_c625 {
  strings:
    $key_c625 = { 95 4a [2] b1 44 [2] 9a 68 [2] b4 4a [2] a0 51 [2] af 4b [2] b1 56 [2] b3 57 [2] a8 51 [2] b4 56 [2] a8 79 }

  condition:
    any of them
}