rule TTP_XOR_QUAD_CurrentVersionRun_4601 {
  strings:
    $key_4601 = { 15 6e [2] 31 60 [2] 1a 4c [2] 34 6e [2] 20 75 [2] 2f 6f [2] 31 72 [2] 33 73 [2] 28 75 [2] 34 72 [2] 28 5d }

  condition:
    any of them
}