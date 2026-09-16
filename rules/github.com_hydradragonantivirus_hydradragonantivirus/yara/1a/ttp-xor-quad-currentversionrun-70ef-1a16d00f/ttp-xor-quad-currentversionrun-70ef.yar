rule TTP_XOR_QUAD_CurrentVersionRun_70ef {
  strings:
    $key_70ef = { 23 80 [2] 07 8e [2] 2c a2 [2] 02 80 [2] 16 9b [2] 19 81 [2] 07 9c [2] 05 9d [2] 1e 9b [2] 02 9c [2] 1e b3 }

  condition:
    any of them
}