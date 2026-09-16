rule TTP_XOR_QUAD_CurrentVersionRun_525c {
  strings:
    $key_525c = { 01 33 [2] 25 3d [2] 0e 11 [2] 20 33 [2] 34 28 [2] 3b 32 [2] 25 2f [2] 27 2e [2] 3c 28 [2] 20 2f [2] 3c 00 }

  condition:
    any of them
}