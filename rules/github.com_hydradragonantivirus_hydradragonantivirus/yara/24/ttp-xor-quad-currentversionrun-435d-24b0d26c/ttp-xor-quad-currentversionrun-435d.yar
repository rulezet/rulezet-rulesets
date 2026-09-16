rule TTP_XOR_QUAD_CurrentVersionRun_435d {
  strings:
    $key_435d = { 10 32 [2] 34 3c [2] 1f 10 [2] 31 32 [2] 25 29 [2] 2a 33 [2] 34 2e [2] 36 2f [2] 2d 29 [2] 31 2e [2] 2d 01 }

  condition:
    any of them
}