rule TTP_XOR_QUAD_CurrentVersionRun_5d6c {
  strings:
    $key_5d6c = { 0e 03 [2] 2a 0d [2] 01 21 [2] 2f 03 [2] 3b 18 [2] 34 02 [2] 2a 1f [2] 28 1e [2] 33 18 [2] 2f 1f [2] 33 30 }

  condition:
    any of them
}