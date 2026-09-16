rule TTP_XOR_QUAD_CurrentVersionRun_e948 {
  strings:
    $key_e948 = { ba 27 [2] 9e 29 [2] b5 05 [2] 9b 27 [2] 8f 3c [2] 80 26 [2] 9e 3b [2] 9c 3a [2] 87 3c [2] 9b 3b [2] 87 14 }

  condition:
    any of them
}