rule TTP_XOR_QUAD_CurrentVersionRun_7863 {
  strings:
    $key_7863 = { 2b 0c [2] 0f 02 [2] 24 2e [2] 0a 0c [2] 1e 17 [2] 11 0d [2] 0f 10 [2] 0d 11 [2] 16 17 [2] 0a 10 [2] 16 3f }

  condition:
    any of them
}