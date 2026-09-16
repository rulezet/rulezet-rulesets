rule TTP_XOR_QUAD_CurrentVersionRun_747f {
  strings:
    $key_747f = { 27 10 [2] 03 1e [2] 28 32 [2] 06 10 [2] 12 0b [2] 1d 11 [2] 03 0c [2] 01 0d [2] 1a 0b [2] 06 0c [2] 1a 23 }

  condition:
    any of them
}