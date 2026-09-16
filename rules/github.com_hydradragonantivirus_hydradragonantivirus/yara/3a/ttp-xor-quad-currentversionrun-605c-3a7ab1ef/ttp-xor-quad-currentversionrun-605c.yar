rule TTP_XOR_QUAD_CurrentVersionRun_605c {
  strings:
    $key_605c = { 33 33 [2] 17 3d [2] 3c 11 [2] 12 33 [2] 06 28 [2] 09 32 [2] 17 2f [2] 15 2e [2] 0e 28 [2] 12 2f [2] 0e 00 }

  condition:
    any of them
}