rule TTP_XOR_QUAD_CurrentVersionRun_68f1 {
  strings:
    $key_68f1 = { 3b 9e [2] 1f 90 [2] 34 bc [2] 1a 9e [2] 0e 85 [2] 01 9f [2] 1f 82 [2] 1d 83 [2] 06 85 [2] 1a 82 [2] 06 ad }

  condition:
    any of them
}