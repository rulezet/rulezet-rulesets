rule TTP_XOR_QUAD_CurrentVersionRun_344c {
  strings:
    $key_344c = { 67 23 [2] 43 2d [2] 68 01 [2] 46 23 [2] 52 38 [2] 5d 22 [2] 43 3f [2] 41 3e [2] 5a 38 [2] 46 3f [2] 5a 10 }

  condition:
    any of them
}