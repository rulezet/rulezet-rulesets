rule TTP_XOR_QUAD_CurrentVersionRun_e5f5 {
  strings:
    $key_e5f5 = { b6 9a [2] 92 94 [2] b9 b8 [2] 97 9a [2] 83 81 [2] 8c 9b [2] 92 86 [2] 90 87 [2] 8b 81 [2] 97 86 [2] 8b a9 }

  condition:
    any of them
}