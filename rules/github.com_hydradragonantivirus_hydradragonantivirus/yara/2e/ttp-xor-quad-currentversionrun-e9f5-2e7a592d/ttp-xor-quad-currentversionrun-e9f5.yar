rule TTP_XOR_QUAD_CurrentVersionRun_e9f5 {
  strings:
    $key_e9f5 = { ba 9a [2] 9e 94 [2] b5 b8 [2] 9b 9a [2] 8f 81 [2] 80 9b [2] 9e 86 [2] 9c 87 [2] 87 81 [2] 9b 86 [2] 87 a9 }

  condition:
    any of them
}