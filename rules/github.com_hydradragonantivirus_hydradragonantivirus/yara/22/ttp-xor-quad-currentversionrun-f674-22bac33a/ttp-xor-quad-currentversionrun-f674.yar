rule TTP_XOR_QUAD_CurrentVersionRun_f674 {
  strings:
    $key_f674 = { a5 1b [2] 81 15 [2] aa 39 [2] 84 1b [2] 90 00 [2] 9f 1a [2] 81 07 [2] 83 06 [2] 98 00 [2] 84 07 [2] 98 28 }

  condition:
    any of them
}