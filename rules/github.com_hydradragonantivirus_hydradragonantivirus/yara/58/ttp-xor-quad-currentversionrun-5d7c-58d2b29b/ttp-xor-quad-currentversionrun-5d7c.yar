rule TTP_XOR_QUAD_CurrentVersionRun_5d7c {
  strings:
    $key_5d7c = { 0e 13 [2] 2a 1d [2] 01 31 [2] 2f 13 [2] 3b 08 [2] 34 12 [2] 2a 0f [2] 28 0e [2] 33 08 [2] 2f 0f [2] 33 20 }

  condition:
    any of them
}