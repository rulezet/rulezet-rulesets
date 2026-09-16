rule TTP_XOR_QUAD_CurrentVersionRun_2de5 {
  strings:
    $key_2de5 = { 7e 8a [2] 5a 84 [2] 71 a8 [2] 5f 8a [2] 4b 91 [2] 44 8b [2] 5a 96 [2] 58 97 [2] 43 91 [2] 5f 96 [2] 43 b9 }

  condition:
    any of them
}