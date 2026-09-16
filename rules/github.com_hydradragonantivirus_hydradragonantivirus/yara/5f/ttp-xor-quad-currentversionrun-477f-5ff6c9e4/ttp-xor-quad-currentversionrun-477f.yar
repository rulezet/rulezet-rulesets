rule TTP_XOR_QUAD_CurrentVersionRun_477f {
  strings:
    $key_477f = { 14 10 [2] 30 1e [2] 1b 32 [2] 35 10 [2] 21 0b [2] 2e 11 [2] 30 0c [2] 32 0d [2] 29 0b [2] 35 0c [2] 29 23 }

  condition:
    any of them
}