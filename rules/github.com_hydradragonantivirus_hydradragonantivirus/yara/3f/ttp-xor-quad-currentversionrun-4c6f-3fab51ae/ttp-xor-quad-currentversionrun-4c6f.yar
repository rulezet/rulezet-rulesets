rule TTP_XOR_QUAD_CurrentVersionRun_4c6f {
  strings:
    $key_4c6f = { 1f 00 [2] 3b 0e [2] 10 22 [2] 3e 00 [2] 2a 1b [2] 25 01 [2] 3b 1c [2] 39 1d [2] 22 1b [2] 3e 1c [2] 22 33 }

  condition:
    any of them
}