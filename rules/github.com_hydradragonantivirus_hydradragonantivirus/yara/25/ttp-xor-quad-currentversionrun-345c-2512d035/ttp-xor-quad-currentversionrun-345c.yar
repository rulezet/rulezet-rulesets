rule TTP_XOR_QUAD_CurrentVersionRun_345c {
  strings:
    $key_345c = { 67 33 [2] 43 3d [2] 68 11 [2] 46 33 [2] 52 28 [2] 5d 32 [2] 43 2f [2] 41 2e [2] 5a 28 [2] 46 2f [2] 5a 00 }

  condition:
    any of them
}