rule TTP_XOR_QUAD_CurrentVersionRun_e927 {
  strings:
    $key_e927 = { ba 48 [2] 9e 46 [2] b5 6a [2] 9b 48 [2] 8f 53 [2] 80 49 [2] 9e 54 [2] 9c 55 [2] 87 53 [2] 9b 54 [2] 87 7b }

  condition:
    any of them
}