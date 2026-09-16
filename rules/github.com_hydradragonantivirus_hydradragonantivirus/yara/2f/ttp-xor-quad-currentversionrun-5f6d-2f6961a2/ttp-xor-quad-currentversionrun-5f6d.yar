rule TTP_XOR_QUAD_CurrentVersionRun_5f6d {
  strings:
    $key_5f6d = { 0c 02 [2] 28 0c [2] 03 20 [2] 2d 02 [2] 39 19 [2] 36 03 [2] 28 1e [2] 2a 1f [2] 31 19 [2] 2d 1e [2] 31 31 }

  condition:
    any of them
}