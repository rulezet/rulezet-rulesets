rule TTP_XOR_QUAD_CurrentVersionRun_711c {
  strings:
    $key_711c = { 22 73 [2] 06 7d [2] 2d 51 [2] 03 73 [2] 17 68 [2] 18 72 [2] 06 6f [2] 04 6e [2] 1f 68 [2] 03 6f [2] 1f 40 }

  condition:
    any of them
}