rule TTP_XOR_QUAD_CurrentVersionRun_e72e {
  strings:
    $key_e72e = { b4 41 [2] 90 4f [2] bb 63 [2] 95 41 [2] 81 5a [2] 8e 40 [2] 90 5d [2] 92 5c [2] 89 5a [2] 95 5d [2] 89 72 }

  condition:
    any of them
}