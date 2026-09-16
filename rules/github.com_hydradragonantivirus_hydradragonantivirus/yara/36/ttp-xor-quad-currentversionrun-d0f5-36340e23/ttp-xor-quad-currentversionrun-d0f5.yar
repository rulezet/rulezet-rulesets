rule TTP_XOR_QUAD_CurrentVersionRun_d0f5 {
  strings:
    $key_d0f5 = { 83 9a [2] a7 94 [2] 8c b8 [2] a2 9a [2] b6 81 [2] b9 9b [2] a7 86 [2] a5 87 [2] be 81 [2] a2 86 [2] be a9 }

  condition:
    any of them
}