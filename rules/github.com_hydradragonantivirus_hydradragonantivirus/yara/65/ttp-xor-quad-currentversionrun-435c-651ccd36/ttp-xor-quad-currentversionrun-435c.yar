rule TTP_XOR_QUAD_CurrentVersionRun_435c {
  strings:
    $key_435c = { 10 33 [2] 34 3d [2] 1f 11 [2] 31 33 [2] 25 28 [2] 2a 32 [2] 34 2f [2] 36 2e [2] 2d 28 [2] 31 2f [2] 2d 00 }

  condition:
    any of them
}