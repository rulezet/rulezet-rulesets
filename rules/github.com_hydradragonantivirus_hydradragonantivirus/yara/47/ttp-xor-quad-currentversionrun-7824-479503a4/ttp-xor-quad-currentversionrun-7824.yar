rule TTP_XOR_QUAD_CurrentVersionRun_7824 {
  strings:
    $key_7824 = { 2b 4b [2] 0f 45 [2] 24 69 [2] 0a 4b [2] 1e 50 [2] 11 4a [2] 0f 57 [2] 0d 56 [2] 16 50 [2] 0a 57 [2] 16 78 }

  condition:
    any of them
}