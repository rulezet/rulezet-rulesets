rule TTP_XOR_QUAD_CurrentVersionRun_1d6f {
  strings:
    $key_1d6f = { 4e 00 [2] 6a 0e [2] 41 22 [2] 6f 00 [2] 7b 1b [2] 74 01 [2] 6a 1c [2] 68 1d [2] 73 1b [2] 6f 1c [2] 73 33 }

  condition:
    any of them
}