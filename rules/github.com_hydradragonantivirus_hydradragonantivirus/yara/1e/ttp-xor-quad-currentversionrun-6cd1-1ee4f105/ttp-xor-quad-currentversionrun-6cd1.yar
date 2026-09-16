rule TTP_XOR_QUAD_CurrentVersionRun_6cd1 {
  strings:
    $key_6cd1 = { 3f be [2] 1b b0 [2] 30 9c [2] 1e be [2] 0a a5 [2] 05 bf [2] 1b a2 [2] 19 a3 [2] 02 a5 [2] 1e a2 [2] 02 8d }

  condition:
    any of them
}