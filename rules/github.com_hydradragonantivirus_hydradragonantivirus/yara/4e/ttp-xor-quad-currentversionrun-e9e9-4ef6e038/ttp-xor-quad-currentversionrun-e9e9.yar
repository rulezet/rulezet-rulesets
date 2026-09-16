rule TTP_XOR_QUAD_CurrentVersionRun_e9e9 {
  strings:
    $key_e9e9 = { ba 86 [2] 9e 88 [2] b5 a4 [2] 9b 86 [2] 8f 9d [2] 80 87 [2] 9e 9a [2] 9c 9b [2] 87 9d [2] 9b 9a [2] 87 b5 }

  condition:
    any of them
}