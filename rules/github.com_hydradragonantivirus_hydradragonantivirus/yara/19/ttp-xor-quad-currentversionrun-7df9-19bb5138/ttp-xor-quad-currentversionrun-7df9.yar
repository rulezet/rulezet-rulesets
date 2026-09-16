rule TTP_XOR_QUAD_CurrentVersionRun_7df9 {
  strings:
    $key_7df9 = { 2e 96 [2] 0a 98 [2] 21 b4 [2] 0f 96 [2] 1b 8d [2] 14 97 [2] 0a 8a [2] 08 8b [2] 13 8d [2] 0f 8a [2] 13 a5 }

  condition:
    any of them
}