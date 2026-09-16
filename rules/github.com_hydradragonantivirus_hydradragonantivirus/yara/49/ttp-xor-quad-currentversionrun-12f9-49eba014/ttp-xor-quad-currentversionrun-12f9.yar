rule TTP_XOR_QUAD_CurrentVersionRun_12f9 {
  strings:
    $key_12f9 = { 41 96 [2] 65 98 [2] 4e b4 [2] 60 96 [2] 74 8d [2] 7b 97 [2] 65 8a [2] 67 8b [2] 7c 8d [2] 60 8a [2] 7c a5 }

  condition:
    any of them
}