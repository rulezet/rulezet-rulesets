rule TTP_XOR_QUAD_CurrentVersionRun_7b71 {
  strings:
    $key_7b71 = { 28 1e [2] 0c 10 [2] 27 3c [2] 09 1e [2] 1d 05 [2] 12 1f [2] 0c 02 [2] 0e 03 [2] 15 05 [2] 09 02 [2] 15 2d }

  condition:
    any of them
}