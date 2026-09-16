rule TTP_XOR_QUAD_CurrentVersionRun_16d7 {
  strings:
    $key_16d7 = { 45 b8 [2] 61 b6 [2] 4a 9a [2] 64 b8 [2] 70 a3 [2] 7f b9 [2] 61 a4 [2] 63 a5 [2] 78 a3 [2] 64 a4 [2] 78 8b }

  condition:
    any of them
}