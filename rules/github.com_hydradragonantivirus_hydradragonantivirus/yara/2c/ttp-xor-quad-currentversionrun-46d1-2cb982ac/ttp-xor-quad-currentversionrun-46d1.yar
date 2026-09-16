rule TTP_XOR_QUAD_CurrentVersionRun_46d1 {
  strings:
    $key_46d1 = { 15 be [2] 31 b0 [2] 1a 9c [2] 34 be [2] 20 a5 [2] 2f bf [2] 31 a2 [2] 33 a3 [2] 28 a5 [2] 34 a2 [2] 28 8d }

  condition:
    any of them
}