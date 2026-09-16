rule TTP_XOR_QUAD_CurrentVersionRun_e9f8 {
  strings:
    $key_e9f8 = { ba 97 [2] 9e 99 [2] b5 b5 [2] 9b 97 [2] 8f 8c [2] 80 96 [2] 9e 8b [2] 9c 8a [2] 87 8c [2] 9b 8b [2] 87 a4 }

  condition:
    any of them
}