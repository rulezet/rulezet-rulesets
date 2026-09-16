rule TTP_XOR_QUAD_CurrentVersionRun_e90b {
  strings:
    $key_e90b = { ba 64 [2] 9e 6a [2] b5 46 [2] 9b 64 [2] 8f 7f [2] 80 65 [2] 9e 78 [2] 9c 79 [2] 87 7f [2] 9b 78 [2] 87 57 }

  condition:
    any of them
}