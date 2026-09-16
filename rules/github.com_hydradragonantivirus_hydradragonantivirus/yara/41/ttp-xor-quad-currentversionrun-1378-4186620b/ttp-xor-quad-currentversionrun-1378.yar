rule TTP_XOR_QUAD_CurrentVersionRun_1378 {
  strings:
    $key_1378 = { 40 17 [2] 64 19 [2] 4f 35 [2] 61 17 [2] 75 0c [2] 7a 16 [2] 64 0b [2] 66 0a [2] 7d 0c [2] 61 0b [2] 7d 24 }

  condition:
    any of them
}