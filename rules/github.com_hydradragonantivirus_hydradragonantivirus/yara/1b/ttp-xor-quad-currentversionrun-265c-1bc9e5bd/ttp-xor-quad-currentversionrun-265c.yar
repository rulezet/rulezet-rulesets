rule TTP_XOR_QUAD_CurrentVersionRun_265c {
  strings:
    $key_265c = { 75 33 [2] 51 3d [2] 7a 11 [2] 54 33 [2] 40 28 [2] 4f 32 [2] 51 2f [2] 53 2e [2] 48 28 [2] 54 2f [2] 48 00 }

  condition:
    any of them
}