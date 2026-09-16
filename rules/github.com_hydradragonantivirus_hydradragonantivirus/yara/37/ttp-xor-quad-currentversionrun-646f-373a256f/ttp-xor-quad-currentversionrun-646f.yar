rule TTP_XOR_QUAD_CurrentVersionRun_646f {
  strings:
    $key_646f = { 37 00 [2] 13 0e [2] 38 22 [2] 16 00 [2] 02 1b [2] 0d 01 [2] 13 1c [2] 11 1d [2] 0a 1b [2] 16 1c [2] 0a 33 }

  condition:
    any of them
}