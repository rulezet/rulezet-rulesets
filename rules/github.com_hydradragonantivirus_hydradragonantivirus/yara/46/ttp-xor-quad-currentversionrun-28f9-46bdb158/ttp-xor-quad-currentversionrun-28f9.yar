rule TTP_XOR_QUAD_CurrentVersionRun_28f9 {
  strings:
    $key_28f9 = { 7b 96 [2] 5f 98 [2] 74 b4 [2] 5a 96 [2] 4e 8d [2] 41 97 [2] 5f 8a [2] 5d 8b [2] 46 8d [2] 5a 8a [2] 46 a5 }

  condition:
    any of them
}