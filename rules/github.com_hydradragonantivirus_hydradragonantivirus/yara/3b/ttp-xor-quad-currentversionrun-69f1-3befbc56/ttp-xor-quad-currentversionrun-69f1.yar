rule TTP_XOR_QUAD_CurrentVersionRun_69f1 {
  strings:
    $key_69f1 = { 3a 9e [2] 1e 90 [2] 35 bc [2] 1b 9e [2] 0f 85 [2] 00 9f [2] 1e 82 [2] 1c 83 [2] 07 85 [2] 1b 82 [2] 07 ad }

  condition:
    any of them
}