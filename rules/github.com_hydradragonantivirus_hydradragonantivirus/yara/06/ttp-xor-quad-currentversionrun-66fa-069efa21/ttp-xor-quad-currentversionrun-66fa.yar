rule TTP_XOR_QUAD_CurrentVersionRun_66fa {
  strings:
    $key_66fa = { 35 95 [2] 11 9b [2] 3a b7 [2] 14 95 [2] 00 8e [2] 0f 94 [2] 11 89 [2] 13 88 [2] 08 8e [2] 14 89 [2] 08 a6 }

  condition:
    any of them
}