rule TTP_XOR_QUAD_CurrentVersionRun_46f1 {
  strings:
    $key_46f1 = { 15 9e [2] 31 90 [2] 1a bc [2] 34 9e [2] 20 85 [2] 2f 9f [2] 31 82 [2] 33 83 [2] 28 85 [2] 34 82 [2] 28 ad }

  condition:
    any of them
}