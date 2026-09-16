rule TTP_XOR_QUAD_CurrentVersionRun_5a71 {
  strings:
    $key_5a71 = { 09 1e [2] 2d 10 [2] 06 3c [2] 28 1e [2] 3c 05 [2] 33 1f [2] 2d 02 [2] 2f 03 [2] 34 05 [2] 28 02 [2] 34 2d }

  condition:
    any of them
}