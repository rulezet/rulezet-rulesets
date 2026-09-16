rule TTP_XOR_QUAD_CurrentVersionRun_6f2f {
  strings:
    $key_6f2f = { 3c 40 [2] 18 4e [2] 33 62 [2] 1d 40 [2] 09 5b [2] 06 41 [2] 18 5c [2] 1a 5d [2] 01 5b [2] 1d 5c [2] 01 73 }

  condition:
    any of them
}