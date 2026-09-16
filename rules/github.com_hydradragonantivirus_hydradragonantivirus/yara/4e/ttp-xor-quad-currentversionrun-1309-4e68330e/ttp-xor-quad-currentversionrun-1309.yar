rule TTP_XOR_QUAD_CurrentVersionRun_1309 {
  strings:
    $key_1309 = { 40 66 [2] 64 68 [2] 4f 44 [2] 61 66 [2] 75 7d [2] 7a 67 [2] 64 7a [2] 66 7b [2] 7d 7d [2] 61 7a [2] 7d 55 }

  condition:
    any of them
}