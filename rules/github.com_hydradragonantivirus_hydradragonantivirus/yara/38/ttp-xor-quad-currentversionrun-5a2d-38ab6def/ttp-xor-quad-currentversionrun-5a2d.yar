rule TTP_XOR_QUAD_CurrentVersionRun_5a2d {
  strings:
    $key_5a2d = { 09 42 [2] 2d 4c [2] 06 60 [2] 28 42 [2] 3c 59 [2] 33 43 [2] 2d 5e [2] 2f 5f [2] 34 59 [2] 28 5e [2] 34 71 }

  condition:
    any of them
}