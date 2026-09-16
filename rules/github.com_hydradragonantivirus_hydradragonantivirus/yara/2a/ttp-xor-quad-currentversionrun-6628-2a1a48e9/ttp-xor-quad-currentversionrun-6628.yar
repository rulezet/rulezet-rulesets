rule TTP_XOR_QUAD_CurrentVersionRun_6628 {
  strings:
    $key_6628 = { 35 47 [2] 11 49 [2] 3a 65 [2] 14 47 [2] 00 5c [2] 0f 46 [2] 11 5b [2] 13 5a [2] 08 5c [2] 14 5b [2] 08 74 }

  condition:
    any of them
}