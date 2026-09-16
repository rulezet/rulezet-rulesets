rule TTP_XOR_QUAD_CurrentVersionRun_3165 {
  strings:
    $key_3165 = { 62 0a [2] 46 04 [2] 6d 28 [2] 43 0a [2] 57 11 [2] 58 0b [2] 46 16 [2] 44 17 [2] 5f 11 [2] 43 16 [2] 5f 39 }

  condition:
    any of them
}