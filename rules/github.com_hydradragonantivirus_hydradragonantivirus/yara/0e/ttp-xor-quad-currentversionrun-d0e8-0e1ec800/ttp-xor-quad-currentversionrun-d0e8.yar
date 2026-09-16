rule TTP_XOR_QUAD_CurrentVersionRun_d0e8 {
  strings:
    $key_d0e8 = { 83 87 [2] a7 89 [2] 8c a5 [2] a2 87 [2] b6 9c [2] b9 86 [2] a7 9b [2] a5 9a [2] be 9c [2] a2 9b [2] be b4 }

  condition:
    any of them
}