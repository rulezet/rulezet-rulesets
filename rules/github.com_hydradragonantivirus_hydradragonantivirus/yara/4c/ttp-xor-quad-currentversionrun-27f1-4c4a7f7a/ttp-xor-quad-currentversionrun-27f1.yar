rule TTP_XOR_QUAD_CurrentVersionRun_27f1 {
  strings:
    $key_27f1 = { 74 9e [2] 50 90 [2] 7b bc [2] 55 9e [2] 41 85 [2] 4e 9f [2] 50 82 [2] 52 83 [2] 49 85 [2] 55 82 [2] 49 ad }

  condition:
    any of them
}