rule TTP_XOR_QUAD_CurrentVersionRun_0f63 {
  strings:
    $key_0f63 = { 5c 0c [2] 78 02 [2] 53 2e [2] 7d 0c [2] 69 17 [2] 66 0d [2] 78 10 [2] 7a 11 [2] 61 17 [2] 7d 10 [2] 61 3f }

  condition:
    any of them
}