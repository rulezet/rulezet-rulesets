rule TTP_XOR_QUAD_CurrentVersionRun_7cd1 {
  strings:
    $key_7cd1 = { 2f be [2] 0b b0 [2] 20 9c [2] 0e be [2] 1a a5 [2] 15 bf [2] 0b a2 [2] 09 a3 [2] 12 a5 [2] 0e a2 [2] 12 8d }

  condition:
    any of them
}