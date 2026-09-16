rule TTP_XOR_QUAD_CurrentVersionRun_602f {
  strings:
    $key_602f = { 33 40 [2] 17 4e [2] 3c 62 [2] 12 40 [2] 06 5b [2] 09 41 [2] 17 5c [2] 15 5d [2] 0e 5b [2] 12 5c [2] 0e 73 }

  condition:
    any of them
}