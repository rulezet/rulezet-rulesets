rule TTP_XOR_QUAD_CurrentVersionRun_7815 {
  strings:
    $key_7815 = { 2b 7a [2] 0f 74 [2] 24 58 [2] 0a 7a [2] 1e 61 [2] 11 7b [2] 0f 66 [2] 0d 67 [2] 16 61 [2] 0a 66 [2] 16 49 }

  condition:
    any of them
}