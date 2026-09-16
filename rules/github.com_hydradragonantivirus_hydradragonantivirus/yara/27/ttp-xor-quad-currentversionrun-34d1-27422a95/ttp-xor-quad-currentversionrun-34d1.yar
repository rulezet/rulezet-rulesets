rule TTP_XOR_QUAD_CurrentVersionRun_34d1 {
  strings:
    $key_34d1 = { 67 be [2] 43 b0 [2] 68 9c [2] 46 be [2] 52 a5 [2] 5d bf [2] 43 a2 [2] 41 a3 [2] 5a a5 [2] 46 a2 [2] 5a 8d }

  condition:
    any of them
}