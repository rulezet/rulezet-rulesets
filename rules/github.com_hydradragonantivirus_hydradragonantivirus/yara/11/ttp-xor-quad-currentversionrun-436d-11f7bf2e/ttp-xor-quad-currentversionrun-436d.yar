rule TTP_XOR_QUAD_CurrentVersionRun_436d {
  strings:
    $key_436d = { 10 02 [2] 34 0c [2] 1f 20 [2] 31 02 [2] 25 19 [2] 2a 03 [2] 34 1e [2] 36 1f [2] 2d 19 [2] 31 1e [2] 2d 31 }

  condition:
    any of them
}