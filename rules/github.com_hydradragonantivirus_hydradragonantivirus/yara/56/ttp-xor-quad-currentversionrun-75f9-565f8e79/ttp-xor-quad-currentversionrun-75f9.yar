rule TTP_XOR_QUAD_CurrentVersionRun_75f9 {
  strings:
    $key_75f9 = { 26 96 [2] 02 98 [2] 29 b4 [2] 07 96 [2] 13 8d [2] 1c 97 [2] 02 8a [2] 00 8b [2] 1b 8d [2] 07 8a [2] 1b a5 }

  condition:
    any of them
}