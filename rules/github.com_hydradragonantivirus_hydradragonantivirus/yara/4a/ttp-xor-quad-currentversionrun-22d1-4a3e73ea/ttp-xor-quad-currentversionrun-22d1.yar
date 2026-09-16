rule TTP_XOR_QUAD_CurrentVersionRun_22d1 {
  strings:
    $key_22d1 = { 71 be [2] 55 b0 [2] 7e 9c [2] 50 be [2] 44 a5 [2] 4b bf [2] 55 a2 [2] 57 a3 [2] 4c a5 [2] 50 a2 [2] 4c 8d }

  condition:
    any of them
}