rule TTP_XOR_QUAD_CurrentVersionRun_32f8 {
  strings:
    $key_32f8 = { 61 97 [2] 45 99 [2] 6e b5 [2] 40 97 [2] 54 8c [2] 5b 96 [2] 45 8b [2] 47 8a [2] 5c 8c [2] 40 8b [2] 5c a4 }

  condition:
    any of them
}