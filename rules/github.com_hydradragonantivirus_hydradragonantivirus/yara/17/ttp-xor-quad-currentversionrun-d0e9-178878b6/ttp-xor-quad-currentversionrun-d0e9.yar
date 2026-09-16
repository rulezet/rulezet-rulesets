rule TTP_XOR_QUAD_CurrentVersionRun_d0e9 {
  strings:
    $key_d0e9 = { 83 86 [2] a7 88 [2] 8c a4 [2] a2 86 [2] b6 9d [2] b9 87 [2] a7 9a [2] a5 9b [2] be 9d [2] a2 9a [2] be b5 }

  condition:
    any of them
}