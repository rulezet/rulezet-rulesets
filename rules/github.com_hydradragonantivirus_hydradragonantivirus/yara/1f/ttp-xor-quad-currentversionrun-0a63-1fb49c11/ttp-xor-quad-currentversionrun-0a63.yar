rule TTP_XOR_QUAD_CurrentVersionRun_0a63 {
  strings:
    $key_0a63 = { 59 0c [2] 7d 02 [2] 56 2e [2] 78 0c [2] 6c 17 [2] 63 0d [2] 7d 10 [2] 7f 11 [2] 64 17 [2] 78 10 [2] 64 3f }

  condition:
    any of them
}