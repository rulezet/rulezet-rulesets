rule TTP_XOR_QUAD_CurrentVersionRun_622f {
  strings:
    $key_622f = { 31 40 [2] 15 4e [2] 3e 62 [2] 10 40 [2] 04 5b [2] 0b 41 [2] 15 5c [2] 17 5d [2] 0c 5b [2] 10 5c [2] 0c 73 }

  condition:
    any of them
}