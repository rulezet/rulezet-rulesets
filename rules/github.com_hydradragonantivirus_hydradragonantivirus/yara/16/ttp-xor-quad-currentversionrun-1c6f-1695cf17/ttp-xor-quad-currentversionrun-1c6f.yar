rule TTP_XOR_QUAD_CurrentVersionRun_1c6f {
  strings:
    $key_1c6f = { 4f 00 [2] 6b 0e [2] 40 22 [2] 6e 00 [2] 7a 1b [2] 75 01 [2] 6b 1c [2] 69 1d [2] 72 1b [2] 6e 1c [2] 72 33 }

  condition:
    any of them
}