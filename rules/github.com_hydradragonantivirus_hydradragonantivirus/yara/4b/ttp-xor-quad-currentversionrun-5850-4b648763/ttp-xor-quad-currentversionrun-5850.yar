rule TTP_XOR_QUAD_CurrentVersionRun_5850 {
  strings:
    $key_5850 = { 0b 3f [2] 2f 31 [2] 04 1d [2] 2a 3f [2] 3e 24 [2] 31 3e [2] 2f 23 [2] 2d 22 [2] 36 24 [2] 2a 23 [2] 36 0c }

  condition:
    any of them
}