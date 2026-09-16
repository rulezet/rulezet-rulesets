rule TTP_XOR_QUAD_CurrentVersionRun_005c {
  strings:
    $key_005c = { 53 33 [2] 77 3d [2] 5c 11 [2] 72 33 [2] 66 28 [2] 69 32 [2] 77 2f [2] 75 2e [2] 6e 28 [2] 72 2f [2] 6e 00 }

  condition:
    any of them
}