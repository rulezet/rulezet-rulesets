rule TTP_XOR_QUAD_CurrentVersionRun_69f8 {
  strings:
    $key_69f8 = { 3a 97 [2] 1e 99 [2] 35 b5 [2] 1b 97 [2] 0f 8c [2] 00 96 [2] 1e 8b [2] 1c 8a [2] 07 8c [2] 1b 8b [2] 07 a4 }

  condition:
    any of them
}