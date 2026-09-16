rule TTP_XOR_QUAD_CurrentVersionRun_75f8 {
  strings:
    $key_75f8 = { 26 97 [2] 02 99 [2] 29 b5 [2] 07 97 [2] 13 8c [2] 1c 96 [2] 02 8b [2] 00 8a [2] 1b 8c [2] 07 8b [2] 1b a4 }

  condition:
    any of them
}