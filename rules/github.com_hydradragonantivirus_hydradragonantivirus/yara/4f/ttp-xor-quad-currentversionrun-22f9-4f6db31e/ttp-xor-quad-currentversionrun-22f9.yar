rule TTP_XOR_QUAD_CurrentVersionRun_22f9 {
  strings:
    $key_22f9 = { 71 96 [2] 55 98 [2] 7e b4 [2] 50 96 [2] 44 8d [2] 4b 97 [2] 55 8a [2] 57 8b [2] 4c 8d [2] 50 8a [2] 4c a5 }

  condition:
    any of them
}