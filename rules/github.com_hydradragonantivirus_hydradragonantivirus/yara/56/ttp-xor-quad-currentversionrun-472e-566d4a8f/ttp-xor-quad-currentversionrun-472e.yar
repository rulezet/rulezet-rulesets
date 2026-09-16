rule TTP_XOR_QUAD_CurrentVersionRun_472e {
  strings:
    $key_472e = { 14 41 [2] 30 4f [2] 1b 63 [2] 35 41 [2] 21 5a [2] 2e 40 [2] 30 5d [2] 32 5c [2] 29 5a [2] 35 5d [2] 29 72 }

  condition:
    any of them
}