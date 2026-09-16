rule TTP_XOR_QUAD_CurrentVersionRun_e936 {
  strings:
    $key_e936 = { ba 59 [2] 9e 57 [2] b5 7b [2] 9b 59 [2] 8f 42 [2] 80 58 [2] 9e 45 [2] 9c 44 [2] 87 42 [2] 9b 45 [2] 87 6a }

  condition:
    any of them
}