rule TTP_XOR_QUAD_CurrentVersionRun_5a50 {
  strings:
    $key_5a50 = { 09 3f [2] 2d 31 [2] 06 1d [2] 28 3f [2] 3c 24 [2] 33 3e [2] 2d 23 [2] 2f 22 [2] 34 24 [2] 28 23 [2] 34 0c }

  condition:
    any of them
}