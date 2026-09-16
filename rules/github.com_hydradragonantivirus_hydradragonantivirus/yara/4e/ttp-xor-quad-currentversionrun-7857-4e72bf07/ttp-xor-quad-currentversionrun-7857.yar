rule TTP_XOR_QUAD_CurrentVersionRun_7857 {
  strings:
    $key_7857 = { 2b 38 [2] 0f 36 [2] 24 1a [2] 0a 38 [2] 1e 23 [2] 11 39 [2] 0f 24 [2] 0d 25 [2] 16 23 [2] 0a 24 [2] 16 0b }

  condition:
    any of them
}