rule TTP_XOR_QUAD_CurrentVersionRun_74f1 {
  strings:
    $key_74f1 = { 27 9e [2] 03 90 [2] 28 bc [2] 06 9e [2] 12 85 [2] 1d 9f [2] 03 82 [2] 01 83 [2] 1a 85 [2] 06 82 [2] 1a ad }

  condition:
    any of them
}