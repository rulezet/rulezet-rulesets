rule TTP_XOR_QUAD_CurrentVersionRun_1615 {
  strings:
    $key_1615 = { 45 7a [2] 61 74 [2] 4a 58 [2] 64 7a [2] 70 61 [2] 7f 7b [2] 61 66 [2] 63 67 [2] 78 61 [2] 64 66 [2] 78 49 }

  condition:
    any of them
}