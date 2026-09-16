rule TTP_XOR_QUAD_CurrentVersionRun_e9f9 {
  strings:
    $key_e9f9 = { ba 96 [2] 9e 98 [2] b5 b4 [2] 9b 96 [2] 8f 8d [2] 80 97 [2] 9e 8a [2] 9c 8b [2] 87 8d [2] 9b 8a [2] 87 a5 }

  condition:
    any of them
}