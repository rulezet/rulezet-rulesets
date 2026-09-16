rule TTP_XOR_QUAD_CurrentVersionRun_5d71 {
  strings:
    $key_5d71 = { 0e 1e [2] 2a 10 [2] 01 3c [2] 2f 1e [2] 3b 05 [2] 34 1f [2] 2a 02 [2] 28 03 [2] 33 05 [2] 2f 02 [2] 33 2d }

  condition:
    any of them
}