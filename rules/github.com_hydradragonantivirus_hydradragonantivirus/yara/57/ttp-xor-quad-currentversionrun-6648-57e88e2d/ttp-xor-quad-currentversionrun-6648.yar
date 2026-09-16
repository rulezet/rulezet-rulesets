rule TTP_XOR_QUAD_CurrentVersionRun_6648 {
  strings:
    $key_6648 = { 35 27 [2] 11 29 [2] 3a 05 [2] 14 27 [2] 00 3c [2] 0f 26 [2] 11 3b [2] 13 3a [2] 08 3c [2] 14 3b [2] 08 14 }

  condition:
    any of them
}