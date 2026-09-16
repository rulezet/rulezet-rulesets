rule TTP_XOR_QUAD_CurrentVersionRun_6608 {
  strings:
    $key_6608 = { 35 67 [2] 11 69 [2] 3a 45 [2] 14 67 [2] 00 7c [2] 0f 66 [2] 11 7b [2] 13 7a [2] 08 7c [2] 14 7b [2] 08 54 }

  condition:
    any of them
}