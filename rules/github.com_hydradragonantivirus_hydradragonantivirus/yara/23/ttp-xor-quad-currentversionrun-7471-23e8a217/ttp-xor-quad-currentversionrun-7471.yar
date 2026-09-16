rule TTP_XOR_QUAD_CurrentVersionRun_7471 {
  strings:
    $key_7471 = { 27 1e [2] 03 10 [2] 28 3c [2] 06 1e [2] 12 05 [2] 1d 1f [2] 03 02 [2] 01 03 [2] 1a 05 [2] 06 02 [2] 1a 2d }

  condition:
    any of them
}