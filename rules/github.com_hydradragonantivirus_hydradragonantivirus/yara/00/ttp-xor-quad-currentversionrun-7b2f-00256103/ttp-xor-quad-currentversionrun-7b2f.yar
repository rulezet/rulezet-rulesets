rule TTP_XOR_QUAD_CurrentVersionRun_7b2f {
  strings:
    $key_7b2f = { 28 40 [2] 0c 4e [2] 27 62 [2] 09 40 [2] 1d 5b [2] 12 41 [2] 0c 5c [2] 0e 5d [2] 15 5b [2] 09 5c [2] 15 73 }

  condition:
    any of them
}