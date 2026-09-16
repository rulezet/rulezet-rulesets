rule TTP_XOR_QUAD_CurrentVersionRun_5d6d {
  strings:
    $key_5d6d = { 0e 02 [2] 2a 0c [2] 01 20 [2] 2f 02 [2] 3b 19 [2] 34 03 [2] 2a 1e [2] 28 1f [2] 33 19 [2] 2f 1e [2] 33 31 }

  condition:
    any of them
}