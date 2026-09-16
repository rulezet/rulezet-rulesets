rule TTP_XOR_QUAD_CurrentVersionRun_693f {
  strings:
    $key_693f = { 3a 50 [2] 1e 5e [2] 35 72 [2] 1b 50 [2] 0f 4b [2] 00 51 [2] 1e 4c [2] 1c 4d [2] 07 4b [2] 1b 4c [2] 07 63 }

  condition:
    any of them
}