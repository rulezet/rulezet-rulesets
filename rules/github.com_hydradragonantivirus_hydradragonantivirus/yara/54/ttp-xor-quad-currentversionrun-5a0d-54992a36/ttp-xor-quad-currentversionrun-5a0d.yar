rule TTP_XOR_QUAD_CurrentVersionRun_5a0d {
  strings:
    $key_5a0d = { 09 62 [2] 2d 6c [2] 06 40 [2] 28 62 [2] 3c 79 [2] 33 63 [2] 2d 7e [2] 2f 7f [2] 34 79 [2] 28 7e [2] 34 51 }

  condition:
    any of them
}