rule TTP_XOR_QUAD_CurrentVersionRun_5d7d {
  strings:
    $key_5d7d = { 0e 12 [2] 2a 1c [2] 01 30 [2] 2f 12 [2] 3b 09 [2] 34 13 [2] 2a 0e [2] 28 0f [2] 33 09 [2] 2f 0e [2] 33 21 }

  condition:
    any of them
}