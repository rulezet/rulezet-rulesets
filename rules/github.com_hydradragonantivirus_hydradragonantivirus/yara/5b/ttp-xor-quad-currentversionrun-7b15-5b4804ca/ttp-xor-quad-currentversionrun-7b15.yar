rule TTP_XOR_QUAD_CurrentVersionRun_7b15 {
  strings:
    $key_7b15 = { 28 7a [2] 0c 74 [2] 27 58 [2] 09 7a [2] 1d 61 [2] 12 7b [2] 0c 66 [2] 0e 67 [2] 15 61 [2] 09 66 [2] 15 49 }

  condition:
    any of them
}