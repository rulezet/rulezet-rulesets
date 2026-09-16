rule TTP_XOR_QUAD_CurrentVersionRun_446c {
  strings:
    $key_446c = { 17 03 [2] 33 0d [2] 18 21 [2] 36 03 [2] 22 18 [2] 2d 02 [2] 33 1f [2] 31 1e [2] 2a 18 [2] 36 1f [2] 2a 30 }

  condition:
    any of them
}