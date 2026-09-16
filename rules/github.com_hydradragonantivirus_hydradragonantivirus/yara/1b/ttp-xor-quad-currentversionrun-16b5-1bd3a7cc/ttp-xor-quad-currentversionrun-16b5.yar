rule TTP_XOR_QUAD_CurrentVersionRun_16b5 {
  strings:
    $key_16b5 = { 45 da [2] 61 d4 [2] 4a f8 [2] 64 da [2] 70 c1 [2] 7f db [2] 61 c6 [2] 63 c7 [2] 78 c1 [2] 64 c6 [2] 78 e9 }

  condition:
    any of them
}