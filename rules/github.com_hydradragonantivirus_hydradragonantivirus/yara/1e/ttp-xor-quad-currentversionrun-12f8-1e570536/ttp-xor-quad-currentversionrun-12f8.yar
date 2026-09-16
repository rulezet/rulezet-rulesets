rule TTP_XOR_QUAD_CurrentVersionRun_12f8 {
  strings:
    $key_12f8 = { 41 97 [2] 65 99 [2] 4e b5 [2] 60 97 [2] 74 8c [2] 7b 96 [2] 65 8b [2] 67 8a [2] 7c 8c [2] 60 8b [2] 7c a4 }

  condition:
    any of them
}