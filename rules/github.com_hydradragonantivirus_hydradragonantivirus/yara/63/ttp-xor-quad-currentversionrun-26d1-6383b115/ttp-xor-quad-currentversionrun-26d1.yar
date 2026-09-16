rule TTP_XOR_QUAD_CurrentVersionRun_26d1 {
  strings:
    $key_26d1 = { 75 be [2] 51 b0 [2] 7a 9c [2] 54 be [2] 40 a5 [2] 4f bf [2] 51 a2 [2] 53 a3 [2] 48 a5 [2] 54 a2 [2] 48 8d }

  condition:
    any of them
}