rule TTP_XOR_QUAD_CurrentVersionRun_e73e {
  strings:
    $key_e73e = { b4 51 [2] 90 5f [2] bb 73 [2] 95 51 [2] 81 4a [2] 8e 50 [2] 90 4d [2] 92 4c [2] 89 4a [2] 95 4d [2] 89 62 }

  condition:
    any of them
}