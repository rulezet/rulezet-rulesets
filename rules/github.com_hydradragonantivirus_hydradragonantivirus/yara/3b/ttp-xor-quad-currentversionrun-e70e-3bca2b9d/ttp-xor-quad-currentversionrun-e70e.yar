rule TTP_XOR_QUAD_CurrentVersionRun_e70e {
  strings:
    $key_e70e = { b4 61 [2] 90 6f [2] bb 43 [2] 95 61 [2] 81 7a [2] 8e 60 [2] 90 7d [2] 92 7c [2] 89 7a [2] 95 7d [2] 89 52 }

  condition:
    any of them
}