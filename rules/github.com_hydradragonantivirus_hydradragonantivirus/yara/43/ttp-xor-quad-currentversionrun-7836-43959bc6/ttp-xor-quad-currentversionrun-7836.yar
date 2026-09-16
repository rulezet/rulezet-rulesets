rule TTP_XOR_QUAD_CurrentVersionRun_7836 {
  strings:
    $key_7836 = { 2b 59 [2] 0f 57 [2] 24 7b [2] 0a 59 [2] 1e 42 [2] 11 58 [2] 0f 45 [2] 0d 44 [2] 16 42 [2] 0a 45 [2] 16 6a }

  condition:
    any of them
}