rule TTP_XOR_QUAD_CurrentVersionRun_66e5 {
  strings:
    $key_66e5 = { 35 8a [2] 11 84 [2] 3a a8 [2] 14 8a [2] 00 91 [2] 0f 8b [2] 11 96 [2] 13 97 [2] 08 91 [2] 14 96 [2] 08 b9 }

  condition:
    any of them
}