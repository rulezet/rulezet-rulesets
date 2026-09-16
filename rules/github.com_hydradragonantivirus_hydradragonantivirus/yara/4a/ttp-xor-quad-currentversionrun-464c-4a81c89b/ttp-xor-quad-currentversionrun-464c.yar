rule TTP_XOR_QUAD_CurrentVersionRun_464c {
  strings:
    $key_464c = { 15 23 [2] 31 2d [2] 1a 01 [2] 34 23 [2] 20 38 [2] 2f 22 [2] 31 3f [2] 33 3e [2] 28 38 [2] 34 3f [2] 28 10 }

  condition:
    any of them
}