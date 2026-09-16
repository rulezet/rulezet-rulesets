rule TTP_XOR_QUAD_CurrentVersionRun_466f {
  strings:
    $key_466f = { 15 00 [2] 31 0e [2] 1a 22 [2] 34 00 [2] 20 1b [2] 2f 01 [2] 31 1c [2] 33 1d [2] 28 1b [2] 34 1c [2] 28 33 }

  condition:
    any of them
}