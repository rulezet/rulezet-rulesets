rule TTP_XOR_QUAD_CurrentVersionRun_45f9 {
  strings:
    $key_45f9 = { 16 96 [2] 32 98 [2] 19 b4 [2] 37 96 [2] 23 8d [2] 2c 97 [2] 32 8a [2] 30 8b [2] 2b 8d [2] 37 8a [2] 2b a5 }

  condition:
    any of them
}