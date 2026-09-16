rule TTP_XOR_QUAD_CurrentVersionRun_7817 {
  strings:
    $key_7817 = { 2b 78 [2] 0f 76 [2] 24 5a [2] 0a 78 [2] 1e 63 [2] 11 79 [2] 0f 64 [2] 0d 65 [2] 16 63 [2] 0a 64 [2] 16 4b }

  condition:
    any of them
}