rule TTP_XOR_QUAD_CurrentVersionRun_477e {
  strings:
    $key_477e = { 14 11 [2] 30 1f [2] 1b 33 [2] 35 11 [2] 21 0a [2] 2e 10 [2] 30 0d [2] 32 0c [2] 29 0a [2] 35 0d [2] 29 22 }

  condition:
    any of them
}