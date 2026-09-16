rule TTP_XOR_QUAD_CurrentVersionRun_7433 {
  strings:
    $key_7433 = { 27 5c [2] 03 52 [2] 28 7e [2] 06 5c [2] 12 47 [2] 1d 5d [2] 03 40 [2] 01 41 [2] 1a 47 [2] 06 40 [2] 1a 6f }

  condition:
    any of them
}