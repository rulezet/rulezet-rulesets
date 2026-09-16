rule TTP_XOR_QUAD_CurrentVersionRun_66f9 {
  strings:
    $key_66f9 = { 35 96 [2] 11 98 [2] 3a b4 [2] 14 96 [2] 00 8d [2] 0f 97 [2] 11 8a [2] 13 8b [2] 08 8d [2] 14 8a [2] 08 a5 }

  condition:
    any of them
}