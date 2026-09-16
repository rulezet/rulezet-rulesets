rule TTP_XOR_QUAD_CurrentVersionRun_f659 {
  strings:
    $key_f659 = { a5 36 [2] 81 38 [2] aa 14 [2] 84 36 [2] 90 2d [2] 9f 37 [2] 81 2a [2] 83 2b [2] 98 2d [2] 84 2a [2] 98 05 }

  condition:
    any of them
}