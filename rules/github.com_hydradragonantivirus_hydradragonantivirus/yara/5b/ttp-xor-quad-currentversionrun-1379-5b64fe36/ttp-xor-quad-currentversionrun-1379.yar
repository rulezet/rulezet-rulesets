rule TTP_XOR_QUAD_CurrentVersionRun_1379 {
  strings:
    $key_1379 = { 40 16 [2] 64 18 [2] 4f 34 [2] 61 16 [2] 75 0d [2] 7a 17 [2] 64 0a [2] 66 0b [2] 7d 0d [2] 61 0a [2] 7d 25 }

  condition:
    any of them
}