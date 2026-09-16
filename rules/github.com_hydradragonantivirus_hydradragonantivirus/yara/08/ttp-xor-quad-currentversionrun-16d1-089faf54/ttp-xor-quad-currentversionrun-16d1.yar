rule TTP_XOR_QUAD_CurrentVersionRun_16d1 {
  strings:
    $key_16d1 = { 45 be [2] 61 b0 [2] 4a 9c [2] 64 be [2] 70 a5 [2] 7f bf [2] 61 a2 [2] 63 a3 [2] 78 a5 [2] 64 a2 [2] 78 8d }

  condition:
    any of them
}