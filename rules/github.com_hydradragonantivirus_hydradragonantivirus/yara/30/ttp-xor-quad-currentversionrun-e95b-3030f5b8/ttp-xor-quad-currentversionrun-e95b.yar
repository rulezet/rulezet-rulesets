rule TTP_XOR_QUAD_CurrentVersionRun_e95b {
  strings:
    $key_e95b = { ba 34 [2] 9e 3a [2] b5 16 [2] 9b 34 [2] 8f 2f [2] 80 35 [2] 9e 28 [2] 9c 29 [2] 87 2f [2] 9b 28 [2] 87 07 }

  condition:
    any of them
}