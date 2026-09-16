rule TTP_XOR_QUAD_CurrentVersionRun_57f1 {
  strings:
    $key_57f1 = { 04 9e [2] 20 90 [2] 0b bc [2] 25 9e [2] 31 85 [2] 3e 9f [2] 20 82 [2] 22 83 [2] 39 85 [2] 25 82 [2] 39 ad }

  condition:
    any of them
}