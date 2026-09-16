rule TTP_XOR_QUAD_CurrentVersionRun_0863 {
  strings:
    $key_0863 = { 5b 0c [2] 7f 02 [2] 54 2e [2] 7a 0c [2] 6e 17 [2] 61 0d [2] 7f 10 [2] 7d 11 [2] 66 17 [2] 7a 10 [2] 66 3f }

  condition:
    any of them
}