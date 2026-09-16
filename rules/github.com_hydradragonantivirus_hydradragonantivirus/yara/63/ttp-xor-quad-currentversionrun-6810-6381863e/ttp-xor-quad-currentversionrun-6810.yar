rule TTP_XOR_QUAD_CurrentVersionRun_6810 {
  strings:
    $key_6810 = { 3b 7f [2] 1f 71 [2] 34 5d [2] 1a 7f [2] 0e 64 [2] 01 7e [2] 1f 63 [2] 1d 62 [2] 06 64 [2] 1a 63 [2] 06 4c }

  condition:
    any of them
}