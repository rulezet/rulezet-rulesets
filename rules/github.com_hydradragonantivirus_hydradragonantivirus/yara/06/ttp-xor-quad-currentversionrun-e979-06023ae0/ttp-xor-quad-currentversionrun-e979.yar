rule TTP_XOR_QUAD_CurrentVersionRun_e979 {
  strings:
    $key_e979 = { ba 16 [2] 9e 18 [2] b5 34 [2] 9b 16 [2] 8f 0d [2] 80 17 [2] 9e 0a [2] 9c 0b [2] 87 0d [2] 9b 0a [2] 87 25 }

  condition:
    any of them
}