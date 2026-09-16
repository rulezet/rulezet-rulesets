rule TTP_XOR_QUAD_CurrentVersionRun_5f1d {
  strings:
    $key_5f1d = { 0c 72 [2] 28 7c [2] 03 50 [2] 2d 72 [2] 39 69 [2] 36 73 [2] 28 6e [2] 2a 6f [2] 31 69 [2] 2d 6e [2] 31 41 }

  condition:
    any of them
}