rule TTP_XOR_QUAD_CurrentVersionRun_2571 {
  strings:
    $key_2571 = { 76 1e [2] 52 10 [2] 79 3c [2] 57 1e [2] 43 05 [2] 4c 1f [2] 52 02 [2] 50 03 [2] 4b 05 [2] 57 02 [2] 4b 2d }

  condition:
    any of them
}