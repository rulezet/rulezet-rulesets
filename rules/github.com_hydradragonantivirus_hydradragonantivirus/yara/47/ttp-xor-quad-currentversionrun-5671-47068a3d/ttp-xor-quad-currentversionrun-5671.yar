rule TTP_XOR_QUAD_CurrentVersionRun_5671 {
  strings:
    $key_5671 = { 05 1e [2] 21 10 [2] 0a 3c [2] 24 1e [2] 30 05 [2] 3f 1f [2] 21 02 [2] 23 03 [2] 38 05 [2] 24 02 [2] 38 2d }

  condition:
    any of them
}