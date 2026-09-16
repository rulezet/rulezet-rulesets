rule TTP_XOR_QUAD_CurrentVersionRun_792c {
  strings:
    $key_792c = { 2a 43 [2] 0e 4d [2] 25 61 [2] 0b 43 [2] 1f 58 [2] 10 42 [2] 0e 5f [2] 0c 5e [2] 17 58 [2] 0b 5f [2] 17 70 }

  condition:
    any of them
}