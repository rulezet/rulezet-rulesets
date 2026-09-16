rule TTP_XOR_QUAD_CurrentVersionRun_e95a {
  strings:
    $key_e95a = { ba 35 [2] 9e 3b [2] b5 17 [2] 9b 35 [2] 8f 2e [2] 80 34 [2] 9e 29 [2] 9c 28 [2] 87 2e [2] 9b 29 [2] 87 06 }

  condition:
    any of them
}