rule TTP_XOR_QUAD_CurrentVersionRun_d025 {
  strings:
    $key_d025 = { 83 4a [2] a7 44 [2] 8c 68 [2] a2 4a [2] b6 51 [2] b9 4b [2] a7 56 [2] a5 57 [2] be 51 [2] a2 56 [2] be 79 }

  condition:
    any of them
}