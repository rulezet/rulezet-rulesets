rule TTP_XOR_QUAD_CurrentVersionRun_7de5 {
  strings:
    $key_7de5 = { 2e 8a [2] 0a 84 [2] 21 a8 [2] 0f 8a [2] 1b 91 [2] 14 8b [2] 0a 96 [2] 08 97 [2] 13 91 [2] 0f 96 [2] 13 b9 }

  condition:
    any of them
}