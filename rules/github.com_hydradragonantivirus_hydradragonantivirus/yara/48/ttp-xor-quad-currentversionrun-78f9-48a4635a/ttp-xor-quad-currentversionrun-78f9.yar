rule TTP_XOR_QUAD_CurrentVersionRun_78f9 {
  strings:
    $key_78f9 = { 2b 96 [2] 0f 98 [2] 24 b4 [2] 0a 96 [2] 1e 8d [2] 11 97 [2] 0f 8a [2] 0d 8b [2] 16 8d [2] 0a 8a [2] 16 a5 }

  condition:
    any of them
}