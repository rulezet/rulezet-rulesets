rule TTP_XOR_QUAD_CurrentVersionRun_412d {
  strings:
    $key_412d = { 12 42 [2] 36 4c [2] 1d 60 [2] 33 42 [2] 27 59 [2] 28 43 [2] 36 5e [2] 34 5f [2] 2f 59 [2] 33 5e [2] 2f 71 }

  condition:
    any of them
}