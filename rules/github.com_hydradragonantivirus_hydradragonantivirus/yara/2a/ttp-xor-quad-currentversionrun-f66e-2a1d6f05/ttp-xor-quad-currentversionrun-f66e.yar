rule TTP_XOR_QUAD_CurrentVersionRun_f66e {
  strings:
    $key_f66e = { a5 01 [2] 81 0f [2] aa 23 [2] 84 01 [2] 90 1a [2] 9f 00 [2] 81 1d [2] 83 1c [2] 98 1a [2] 84 1d [2] 98 32 }

  condition:
    any of them
}