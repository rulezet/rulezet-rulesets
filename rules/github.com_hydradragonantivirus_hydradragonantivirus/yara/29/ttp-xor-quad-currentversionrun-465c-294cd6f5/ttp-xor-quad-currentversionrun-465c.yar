rule TTP_XOR_QUAD_CurrentVersionRun_465c {
  strings:
    $key_465c = { 15 33 [2] 31 3d [2] 1a 11 [2] 34 33 [2] 20 28 [2] 2f 32 [2] 31 2f [2] 33 2e [2] 28 28 [2] 34 2f [2] 28 00 }

  condition:
    any of them
}