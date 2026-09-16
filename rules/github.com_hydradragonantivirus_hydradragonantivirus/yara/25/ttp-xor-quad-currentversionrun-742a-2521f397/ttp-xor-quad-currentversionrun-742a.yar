rule TTP_XOR_QUAD_CurrentVersionRun_742a {
  strings:
    $key_742a = { 27 45 [2] 03 4b [2] 28 67 [2] 06 45 [2] 12 5e [2] 1d 44 [2] 03 59 [2] 01 58 [2] 1a 5e [2] 06 59 [2] 1a 76 }

  condition:
    any of them
}