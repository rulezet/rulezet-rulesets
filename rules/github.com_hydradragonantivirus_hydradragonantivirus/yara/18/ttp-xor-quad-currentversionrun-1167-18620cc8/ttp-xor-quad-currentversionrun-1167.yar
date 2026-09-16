rule TTP_XOR_QUAD_CurrentVersionRun_1167 {
  strings:
    $key_1167 = { 42 08 [2] 66 06 [2] 4d 2a [2] 63 08 [2] 77 13 [2] 78 09 [2] 66 14 [2] 64 15 [2] 7f 13 [2] 63 14 [2] 7f 3b }

  condition:
    any of them
}