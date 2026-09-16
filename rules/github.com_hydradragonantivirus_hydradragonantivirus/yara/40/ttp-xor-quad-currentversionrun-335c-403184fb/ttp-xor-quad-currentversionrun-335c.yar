rule TTP_XOR_QUAD_CurrentVersionRun_335c {
  strings:
    $key_335c = { 60 33 [2] 44 3d [2] 6f 11 [2] 41 33 [2] 55 28 [2] 5a 32 [2] 44 2f [2] 46 2e [2] 5d 28 [2] 41 2f [2] 5d 00 }

  condition:
    any of them
}