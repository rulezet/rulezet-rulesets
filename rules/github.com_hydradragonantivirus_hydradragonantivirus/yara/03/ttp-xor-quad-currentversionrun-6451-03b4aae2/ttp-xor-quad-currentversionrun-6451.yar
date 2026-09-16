rule TTP_XOR_QUAD_CurrentVersionRun_6451 {
  strings:
    $key_6451 = { 37 3e [2] 13 30 [2] 38 1c [2] 16 3e [2] 02 25 [2] 0d 3f [2] 13 22 [2] 11 23 [2] 0a 25 [2] 16 22 [2] 0a 0d }

  condition:
    any of them
}