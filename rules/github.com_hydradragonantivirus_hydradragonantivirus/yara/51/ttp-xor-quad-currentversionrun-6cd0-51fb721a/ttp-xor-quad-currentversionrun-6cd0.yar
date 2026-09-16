rule TTP_XOR_QUAD_CurrentVersionRun_6cd0 {
  strings:
    $key_6cd0 = { 3f bf [2] 1b b1 [2] 30 9d [2] 1e bf [2] 0a a4 [2] 05 be [2] 1b a3 [2] 19 a2 [2] 02 a4 [2] 1e a3 [2] 02 8c }

  condition:
    any of them
}