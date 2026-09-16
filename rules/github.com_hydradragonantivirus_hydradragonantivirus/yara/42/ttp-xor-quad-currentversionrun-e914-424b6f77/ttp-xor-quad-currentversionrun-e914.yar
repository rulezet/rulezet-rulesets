rule TTP_XOR_QUAD_CurrentVersionRun_e914 {
  strings:
    $key_e914 = { ba 7b [2] 9e 75 [2] b5 59 [2] 9b 7b [2] 8f 60 [2] 80 7a [2] 9e 67 [2] 9c 66 [2] 87 60 [2] 9b 67 [2] 87 48 }

  condition:
    any of them
}