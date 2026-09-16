rule TTP_XOR_QUAD_CurrentVersionRun_1365 {
  strings:
    $key_1365 = { 40 0a [2] 64 04 [2] 4f 28 [2] 61 0a [2] 75 11 [2] 7a 0b [2] 64 16 [2] 66 17 [2] 7d 11 [2] 61 16 [2] 7d 39 }

  condition:
    any of them
}