rule TTP_XOR_QUAD_CurrentVersionRun_472f {
  strings:
    $key_472f = { 14 40 [2] 30 4e [2] 1b 62 [2] 35 40 [2] 21 5b [2] 2e 41 [2] 30 5c [2] 32 5d [2] 29 5b [2] 35 5c [2] 29 73 }

  condition:
    any of them
}