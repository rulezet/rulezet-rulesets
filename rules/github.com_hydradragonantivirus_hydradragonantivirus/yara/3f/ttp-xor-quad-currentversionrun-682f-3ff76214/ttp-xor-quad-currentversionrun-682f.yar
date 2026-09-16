rule TTP_XOR_QUAD_CurrentVersionRun_682f {
  strings:
    $key_682f = { 3b 40 [2] 1f 4e [2] 34 62 [2] 1a 40 [2] 0e 5b [2] 01 41 [2] 1f 5c [2] 1d 5d [2] 06 5b [2] 1a 5c [2] 06 73 }

  condition:
    any of them
}