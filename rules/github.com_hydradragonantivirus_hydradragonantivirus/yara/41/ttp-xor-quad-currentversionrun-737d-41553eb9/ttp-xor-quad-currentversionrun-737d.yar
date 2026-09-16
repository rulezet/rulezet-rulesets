rule TTP_XOR_QUAD_CurrentVersionRun_737d {
  strings:
    $key_737d = { 20 12 [2] 04 1c [2] 2f 30 [2] 01 12 [2] 15 09 [2] 1a 13 [2] 04 0e [2] 06 0f [2] 1d 09 [2] 01 0e [2] 1d 21 }

  condition:
    any of them
}