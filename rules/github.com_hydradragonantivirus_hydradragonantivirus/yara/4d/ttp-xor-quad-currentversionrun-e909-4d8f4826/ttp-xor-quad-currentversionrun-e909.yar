rule TTP_XOR_QUAD_CurrentVersionRun_e909 {
  strings:
    $key_e909 = { ba 66 [2] 9e 68 [2] b5 44 [2] 9b 66 [2] 8f 7d [2] 80 67 [2] 9e 7a [2] 9c 7b [2] 87 7d [2] 9b 7a [2] 87 55 }

  condition:
    any of them
}