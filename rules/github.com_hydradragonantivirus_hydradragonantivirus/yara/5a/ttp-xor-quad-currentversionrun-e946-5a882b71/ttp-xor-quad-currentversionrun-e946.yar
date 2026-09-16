rule TTP_XOR_QUAD_CurrentVersionRun_e946 {
  strings:
    $key_e946 = { ba 29 [2] 9e 27 [2] b5 0b [2] 9b 29 [2] 8f 32 [2] 80 28 [2] 9e 35 [2] 9c 34 [2] 87 32 [2] 9b 35 [2] 87 1a }

  condition:
    any of them
}