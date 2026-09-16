rule TTP_XOR_QUAD_CurrentVersionRun_4e2d {
  strings:
    $key_4e2d = { 1d 42 [2] 39 4c [2] 12 60 [2] 3c 42 [2] 28 59 [2] 27 43 [2] 39 5e [2] 3b 5f [2] 20 59 [2] 3c 5e [2] 20 71 }

  condition:
    any of them
}