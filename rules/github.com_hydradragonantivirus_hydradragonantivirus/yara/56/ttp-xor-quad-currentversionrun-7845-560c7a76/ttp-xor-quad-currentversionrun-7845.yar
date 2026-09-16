rule TTP_XOR_QUAD_CurrentVersionRun_7845 {
  strings:
    $key_7845 = { 2b 2a [2] 0f 24 [2] 24 08 [2] 0a 2a [2] 1e 31 [2] 11 2b [2] 0f 36 [2] 0d 37 [2] 16 31 [2] 0a 36 [2] 16 19 }

  condition:
    any of them
}