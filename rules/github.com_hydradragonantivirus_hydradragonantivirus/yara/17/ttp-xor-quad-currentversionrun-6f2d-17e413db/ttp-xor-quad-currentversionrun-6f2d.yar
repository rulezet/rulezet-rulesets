rule TTP_XOR_QUAD_CurrentVersionRun_6f2d {
  strings:
    $key_6f2d = { 3c 42 [2] 18 4c [2] 33 60 [2] 1d 42 [2] 09 59 [2] 06 43 [2] 18 5e [2] 1a 5f [2] 01 59 [2] 1d 5e [2] 01 71 }

  condition:
    any of them
}