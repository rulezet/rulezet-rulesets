rule TTP_XOR_QUAD_CurrentVersionRun_7804 {
  strings:
    $key_7804 = { 2b 6b [2] 0f 65 [2] 24 49 [2] 0a 6b [2] 1e 70 [2] 11 6a [2] 0f 77 [2] 0d 76 [2] 16 70 [2] 0a 77 [2] 16 58 }

  condition:
    any of them
}