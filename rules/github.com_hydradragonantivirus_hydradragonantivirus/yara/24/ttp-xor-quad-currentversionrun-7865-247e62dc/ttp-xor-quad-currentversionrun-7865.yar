rule TTP_XOR_QUAD_CurrentVersionRun_7865 {
  strings:
    $key_7865 = { 2b 0a [2] 0f 04 [2] 24 28 [2] 0a 0a [2] 1e 11 [2] 11 0b [2] 0f 16 [2] 0d 17 [2] 16 11 [2] 0a 16 [2] 16 39 }

  condition:
    any of them
}