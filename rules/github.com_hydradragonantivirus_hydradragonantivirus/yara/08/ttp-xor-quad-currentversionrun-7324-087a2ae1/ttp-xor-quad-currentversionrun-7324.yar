rule TTP_XOR_QUAD_CurrentVersionRun_7324 {
  strings:
    $key_7324 = { 20 4b [2] 04 45 [2] 2f 69 [2] 01 4b [2] 15 50 [2] 1a 4a [2] 04 57 [2] 06 56 [2] 1d 50 [2] 01 57 [2] 1d 78 }

  condition:
    any of them
}