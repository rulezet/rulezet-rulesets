rule TTP_XOR_QUAD_CurrentVersionRun_d065 {
  strings:
    $key_d065 = { 83 0a [2] a7 04 [2] 8c 28 [2] a2 0a [2] b6 11 [2] b9 0b [2] a7 16 [2] a5 17 [2] be 11 [2] a2 16 [2] be 39 }

  condition:
    any of them
}