rule TTP_XOR_QUAD_CurrentVersionRun_1115 {
  strings:
    $key_1115 = { 42 7a [2] 66 74 [2] 4d 58 [2] 63 7a [2] 77 61 [2] 78 7b [2] 66 66 [2] 64 67 [2] 7f 61 [2] 63 66 [2] 7f 49 }

  condition:
    any of them
}