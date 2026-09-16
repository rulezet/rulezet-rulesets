rule TTP_XOR_QUAD_CurrentVersionRun_740d {
  strings:
    $key_740d = { 27 62 [2] 03 6c [2] 28 40 [2] 06 62 [2] 12 79 [2] 1d 63 [2] 03 7e [2] 01 7f [2] 1a 79 [2] 06 7e [2] 1a 51 }

  condition:
    any of them
}