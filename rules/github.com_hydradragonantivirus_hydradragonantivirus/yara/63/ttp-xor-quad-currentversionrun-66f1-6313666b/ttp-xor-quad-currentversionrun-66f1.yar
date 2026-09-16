rule TTP_XOR_QUAD_CurrentVersionRun_66f1 {
  strings:
    $key_66f1 = { 35 9e [2] 11 90 [2] 3a bc [2] 14 9e [2] 00 85 [2] 0f 9f [2] 11 82 [2] 13 83 [2] 08 85 [2] 14 82 [2] 08 ad }

  condition:
    any of them
}