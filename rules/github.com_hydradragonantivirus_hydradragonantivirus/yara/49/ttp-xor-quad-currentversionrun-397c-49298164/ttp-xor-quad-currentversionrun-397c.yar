rule TTP_XOR_QUAD_CurrentVersionRun_397c {
  strings:
    $key_397c = { 6a 13 [2] 4e 1d [2] 65 31 [2] 4b 13 [2] 5f 08 [2] 50 12 [2] 4e 0f [2] 4c 0e [2] 57 08 [2] 4b 0f [2] 57 20 }

  condition:
    any of them
}