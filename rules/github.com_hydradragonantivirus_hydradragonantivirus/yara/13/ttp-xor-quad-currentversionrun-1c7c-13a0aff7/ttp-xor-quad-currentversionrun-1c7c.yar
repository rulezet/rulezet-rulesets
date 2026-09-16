rule TTP_XOR_QUAD_CurrentVersionRun_1c7c {
  strings:
    $key_1c7c = { 4f 13 [2] 6b 1d [2] 40 31 [2] 6e 13 [2] 7a 08 [2] 75 12 [2] 6b 0f [2] 69 0e [2] 72 08 [2] 6e 0f [2] 72 20 }

  condition:
    any of them
}