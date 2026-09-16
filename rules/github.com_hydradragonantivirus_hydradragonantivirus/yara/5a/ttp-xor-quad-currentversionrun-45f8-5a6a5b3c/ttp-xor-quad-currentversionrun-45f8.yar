rule TTP_XOR_QUAD_CurrentVersionRun_45f8 {
  strings:
    $key_45f8 = { 16 97 [2] 32 99 [2] 19 b5 [2] 37 97 [2] 23 8c [2] 2c 96 [2] 32 8b [2] 30 8a [2] 2b 8c [2] 37 8b [2] 2b a4 }

  condition:
    any of them
}