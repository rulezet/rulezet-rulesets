rule TTP_XOR_QUAD_CurrentVersionRun_1cd1 {
  strings:
    $key_1cd1 = { 4f be [2] 6b b0 [2] 40 9c [2] 6e be [2] 7a a5 [2] 75 bf [2] 6b a2 [2] 69 a3 [2] 72 a5 [2] 6e a2 [2] 72 8d }

  condition:
    any of them
}