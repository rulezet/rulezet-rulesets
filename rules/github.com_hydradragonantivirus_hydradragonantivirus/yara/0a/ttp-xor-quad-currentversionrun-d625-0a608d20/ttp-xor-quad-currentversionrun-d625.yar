rule TTP_XOR_QUAD_CurrentVersionRun_d625 {
  strings:
    $key_d625 = { 85 4a [2] a1 44 [2] 8a 68 [2] a4 4a [2] b0 51 [2] bf 4b [2] a1 56 [2] a3 57 [2] b8 51 [2] a4 56 [2] b8 79 }

  condition:
    any of them
}