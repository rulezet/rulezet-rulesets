rule TTP_XOR_QUAD_CurrentVersionRun_526f {
  strings:
    $key_526f = { 01 00 [2] 25 0e [2] 0e 22 [2] 20 00 [2] 34 1b [2] 3b 01 [2] 25 1c [2] 27 1d [2] 3c 1b [2] 20 1c [2] 3c 33 }

  condition:
    any of them
}