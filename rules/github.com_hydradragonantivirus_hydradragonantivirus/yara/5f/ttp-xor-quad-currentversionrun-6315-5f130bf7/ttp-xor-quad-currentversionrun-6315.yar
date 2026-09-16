rule TTP_XOR_QUAD_CurrentVersionRun_6315 {
  strings:
    $key_6315 = { 30 7a [2] 14 74 [2] 3f 58 [2] 11 7a [2] 05 61 [2] 0a 7b [2] 14 66 [2] 16 67 [2] 0d 61 [2] 11 66 [2] 0d 49 }

  condition:
    any of them
}