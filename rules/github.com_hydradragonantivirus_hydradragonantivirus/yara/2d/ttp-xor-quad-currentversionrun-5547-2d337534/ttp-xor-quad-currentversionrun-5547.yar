rule TTP_XOR_QUAD_CurrentVersionRun_5547 {
  strings:
    $key_5547 = { 06 28 [2] 22 26 [2] 09 0a [2] 27 28 [2] 33 33 [2] 3c 29 [2] 22 34 [2] 20 35 [2] 3b 33 [2] 27 34 [2] 3b 1b }

  condition:
    any of them
}