rule TTP_XOR_QUAD_CurrentVersionRun_7df8 {
  strings:
    $key_7df8 = { 2e 97 [2] 0a 99 [2] 21 b5 [2] 0f 97 [2] 1b 8c [2] 14 96 [2] 0a 8b [2] 08 8a [2] 13 8c [2] 0f 8b [2] 13 a4 }

  condition:
    any of them
}