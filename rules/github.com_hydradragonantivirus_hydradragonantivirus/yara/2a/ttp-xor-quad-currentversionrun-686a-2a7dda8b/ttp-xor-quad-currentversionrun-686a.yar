rule TTP_XOR_QUAD_CurrentVersionRun_686a {
  strings:
    $key_686a = { 3b 05 [2] 1f 0b [2] 34 27 [2] 1a 05 [2] 0e 1e [2] 01 04 [2] 1f 19 [2] 1d 18 [2] 06 1e [2] 1a 19 [2] 06 36 }

  condition:
    any of them
}