rule TTP_XOR_QUAD_CurrentVersionRun_4b6f {
  strings:
    $key_4b6f = { 18 00 [2] 3c 0e [2] 17 22 [2] 39 00 [2] 2d 1b [2] 22 01 [2] 3c 1c [2] 3e 1d [2] 25 1b [2] 39 1c [2] 25 33 }

  condition:
    any of them
}