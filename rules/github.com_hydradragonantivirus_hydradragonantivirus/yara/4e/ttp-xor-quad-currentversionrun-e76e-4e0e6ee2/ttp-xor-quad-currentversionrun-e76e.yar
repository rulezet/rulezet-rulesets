rule TTP_XOR_QUAD_CurrentVersionRun_e76e {
  strings:
    $key_e76e = { b4 01 [2] 90 0f [2] bb 23 [2] 95 01 [2] 81 1a [2] 8e 00 [2] 90 1d [2] 92 1c [2] 89 1a [2] 95 1d [2] 89 32 }

  condition:
    any of them
}