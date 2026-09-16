rule TTP_XOR_QUAD_CurrentVersionRun_1408 {
  strings:
    $key_1408 = { 47 67 [2] 63 69 [2] 48 45 [2] 66 67 [2] 72 7c [2] 7d 66 [2] 63 7b [2] 61 7a [2] 7a 7c [2] 66 7b [2] 7a 54 }

  condition:
    any of them
}