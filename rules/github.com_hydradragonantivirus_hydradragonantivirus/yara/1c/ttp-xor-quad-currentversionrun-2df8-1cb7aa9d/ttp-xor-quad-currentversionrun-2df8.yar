rule TTP_XOR_QUAD_CurrentVersionRun_2df8 {
  strings:
    $key_2df8 = { 7e 97 [2] 5a 99 [2] 71 b5 [2] 5f 97 [2] 4b 8c [2] 44 96 [2] 5a 8b [2] 58 8a [2] 43 8c [2] 5f 8b [2] 43 a4 }

  condition:
    any of them
}