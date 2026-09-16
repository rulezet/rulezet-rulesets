rule TTP_XOR_QUAD_CurrentVersionRun_7c5c {
  strings:
    $key_7c5c = { 2f 33 [2] 0b 3d [2] 20 11 [2] 0e 33 [2] 1a 28 [2] 15 32 [2] 0b 2f [2] 09 2e [2] 12 28 [2] 0e 2f [2] 12 00 }

  condition:
    any of them
}