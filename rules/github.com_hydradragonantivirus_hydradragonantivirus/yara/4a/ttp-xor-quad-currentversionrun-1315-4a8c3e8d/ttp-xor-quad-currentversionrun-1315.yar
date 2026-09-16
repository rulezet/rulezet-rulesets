rule TTP_XOR_QUAD_CurrentVersionRun_1315 {
  strings:
    $key_1315 = { 40 7a [2] 64 74 [2] 4f 58 [2] 61 7a [2] 75 61 [2] 7a 7b [2] 64 66 [2] 66 67 [2] 7d 61 [2] 61 66 [2] 7d 49 }

  condition:
    any of them
}