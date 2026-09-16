rule TTP_XOR_QUAD_CurrentVersionRun_15f8 {
  strings:
    $key_15f8 = { 46 97 [2] 62 99 [2] 49 b5 [2] 67 97 [2] 73 8c [2] 7c 96 [2] 62 8b [2] 60 8a [2] 7b 8c [2] 67 8b [2] 7b a4 }

  condition:
    any of them
}