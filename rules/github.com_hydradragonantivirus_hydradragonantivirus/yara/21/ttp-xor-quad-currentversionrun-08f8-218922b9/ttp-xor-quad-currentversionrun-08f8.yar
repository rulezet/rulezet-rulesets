rule TTP_XOR_QUAD_CurrentVersionRun_08f8 {
  strings:
    $key_08f8 = { 5b 97 [2] 7f 99 [2] 54 b5 [2] 7a 97 [2] 6e 8c [2] 61 96 [2] 7f 8b [2] 7d 8a [2] 66 8c [2] 7a 8b [2] 66 a4 }

  condition:
    any of them
}