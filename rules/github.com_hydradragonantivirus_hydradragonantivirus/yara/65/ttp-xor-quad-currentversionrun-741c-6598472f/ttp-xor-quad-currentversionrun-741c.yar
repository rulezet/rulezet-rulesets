rule TTP_XOR_QUAD_CurrentVersionRun_741c {
  strings:
    $key_741c = { 27 73 [2] 03 7d [2] 28 51 [2] 06 73 [2] 12 68 [2] 1d 72 [2] 03 6f [2] 01 6e [2] 1a 68 [2] 06 6f [2] 1a 40 }

  condition:
    any of them
}