rule TTP_XOR_QUAD_CurrentVersionRun_527f {
  strings:
    $key_527f = { 01 10 [2] 25 1e [2] 0e 32 [2] 20 10 [2] 34 0b [2] 3b 11 [2] 25 0c [2] 27 0d [2] 3c 0b [2] 20 0c [2] 3c 23 }

  condition:
    any of them
}