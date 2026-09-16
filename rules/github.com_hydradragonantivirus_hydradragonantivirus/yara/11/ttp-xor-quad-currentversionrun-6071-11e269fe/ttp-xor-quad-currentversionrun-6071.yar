rule TTP_XOR_QUAD_CurrentVersionRun_6071 {
  strings:
    $key_6071 = { 33 1e [2] 17 10 [2] 3c 3c [2] 12 1e [2] 06 05 [2] 09 1f [2] 17 02 [2] 15 03 [2] 0e 05 [2] 12 02 [2] 0e 2d }

  condition:
    any of them
}