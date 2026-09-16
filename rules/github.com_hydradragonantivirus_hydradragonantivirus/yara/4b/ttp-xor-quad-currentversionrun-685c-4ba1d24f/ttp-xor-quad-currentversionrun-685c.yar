rule TTP_XOR_QUAD_CurrentVersionRun_685c {
  strings:
    $key_685c = { 3b 33 [2] 1f 3d [2] 34 11 [2] 1a 33 [2] 0e 28 [2] 01 32 [2] 1f 2f [2] 1d 2e [2] 06 28 [2] 1a 2f [2] 06 00 }

  condition:
    any of them
}