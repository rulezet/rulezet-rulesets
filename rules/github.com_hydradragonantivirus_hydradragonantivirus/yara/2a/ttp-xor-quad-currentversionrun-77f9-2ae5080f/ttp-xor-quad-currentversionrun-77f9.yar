rule TTP_XOR_QUAD_CurrentVersionRun_77f9 {
  strings:
    $key_77f9 = { 24 96 [2] 00 98 [2] 2b b4 [2] 05 96 [2] 11 8d [2] 1e 97 [2] 00 8a [2] 02 8b [2] 19 8d [2] 05 8a [2] 19 a5 }

  condition:
    any of them
}