rule TTP_XOR_QUAD_CurrentVersionRun_1571 {
  strings:
    $key_1571 = { 46 1e [2] 62 10 [2] 49 3c [2] 67 1e [2] 73 05 [2] 7c 1f [2] 62 02 [2] 60 03 [2] 7b 05 [2] 67 02 [2] 7b 2d }

  condition:
    any of them
}