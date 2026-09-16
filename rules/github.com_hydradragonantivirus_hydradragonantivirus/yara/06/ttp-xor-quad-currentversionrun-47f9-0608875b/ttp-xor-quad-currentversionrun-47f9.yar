rule TTP_XOR_QUAD_CurrentVersionRun_47f9 {
  strings:
    $key_47f9 = { 14 96 [2] 30 98 [2] 1b b4 [2] 35 96 [2] 21 8d [2] 2e 97 [2] 30 8a [2] 32 8b [2] 29 8d [2] 35 8a [2] 29 a5 }

  condition:
    any of them
}