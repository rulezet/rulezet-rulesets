rule TTP_XOR_QUAD_CurrentVersionRun_406f {
  strings:
    $key_406f = { 13 00 [2] 37 0e [2] 1c 22 [2] 32 00 [2] 26 1b [2] 29 01 [2] 37 1c [2] 35 1d [2] 2e 1b [2] 32 1c [2] 2e 33 }

  condition:
    any of them
}