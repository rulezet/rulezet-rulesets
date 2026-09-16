rule TTP_XOR_QUAD_CurrentVersionRun_0450 {
  strings:
    $key_0450 = { 57 3f [2] 73 31 [2] 58 1d [2] 76 3f [2] 62 24 [2] 6d 3e [2] 73 23 [2] 71 22 [2] 6a 24 [2] 76 23 [2] 6a 0c }

  condition:
    any of them
}