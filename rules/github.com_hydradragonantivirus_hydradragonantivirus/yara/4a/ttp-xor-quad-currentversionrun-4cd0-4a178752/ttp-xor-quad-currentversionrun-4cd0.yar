rule TTP_XOR_QUAD_CurrentVersionRun_4cd0 {
  strings:
    $key_4cd0 = { 1f bf [2] 3b b1 [2] 10 9d [2] 3e bf [2] 2a a4 [2] 25 be [2] 3b a3 [2] 39 a2 [2] 22 a4 [2] 3e a3 [2] 22 8c }

  condition:
    any of them
}