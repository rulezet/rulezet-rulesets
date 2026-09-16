rule TTP_XOR_QUAD_CurrentVersionRun_e71e {
  strings:
    $key_e71e = { b4 71 [2] 90 7f [2] bb 53 [2] 95 71 [2] 81 6a [2] 8e 70 [2] 90 6d [2] 92 6c [2] 89 6a [2] 95 6d [2] 89 42 }

  condition:
    any of them
}