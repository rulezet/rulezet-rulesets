rule TTP_XOR_QUAD_CurrentVersionRun_77ef {
  strings:
    $key_77ef = { 24 80 [2] 00 8e [2] 2b a2 [2] 05 80 [2] 11 9b [2] 1e 81 [2] 00 9c [2] 02 9d [2] 19 9b [2] 05 9c [2] 19 b3 }

  condition:
    any of them
}