rule TTP_XOR_QUAD_CurrentVersionRun_5576 {
  strings:
    $key_5576 = { 06 19 [2] 22 17 [2] 09 3b [2] 27 19 [2] 33 02 [2] 3c 18 [2] 22 05 [2] 20 04 [2] 3b 02 [2] 27 05 [2] 3b 2a }

  condition:
    any of them
}