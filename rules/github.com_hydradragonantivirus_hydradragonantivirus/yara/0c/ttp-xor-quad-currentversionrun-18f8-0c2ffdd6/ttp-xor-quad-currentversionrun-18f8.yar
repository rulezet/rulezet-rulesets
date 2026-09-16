rule TTP_XOR_QUAD_CurrentVersionRun_18f8 {
  strings:
    $key_18f8 = { 4b 97 [2] 6f 99 [2] 44 b5 [2] 6a 97 [2] 7e 8c [2] 71 96 [2] 6f 8b [2] 6d 8a [2] 76 8c [2] 6a 8b [2] 76 a4 }

  condition:
    any of them
}