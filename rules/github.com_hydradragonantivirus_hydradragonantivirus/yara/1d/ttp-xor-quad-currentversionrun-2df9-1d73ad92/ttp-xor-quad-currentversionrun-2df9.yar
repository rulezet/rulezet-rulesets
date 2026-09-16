rule TTP_XOR_QUAD_CurrentVersionRun_2df9 {
  strings:
    $key_2df9 = { 7e 96 [2] 5a 98 [2] 71 b4 [2] 5f 96 [2] 4b 8d [2] 44 97 [2] 5a 8a [2] 58 8b [2] 43 8d [2] 5f 8a [2] 43 a5 }

  condition:
    any of them
}