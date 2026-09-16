rule TTP_XOR_QUAD_CurrentVersionRun_1cd0 {
  strings:
    $key_1cd0 = { 4f bf [2] 6b b1 [2] 40 9d [2] 6e bf [2] 7a a4 [2] 75 be [2] 6b a3 [2] 69 a2 [2] 72 a4 [2] 6e a3 [2] 72 8c }

  condition:
    any of them
}