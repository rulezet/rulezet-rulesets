rule TTP_XOR_QUAD_CurrentVersionRun_2de9 {
  strings:
    $key_2de9 = { 7e 86 [2] 5a 88 [2] 71 a4 [2] 5f 86 [2] 4b 9d [2] 44 87 [2] 5a 9a [2] 58 9b [2] 43 9d [2] 5f 9a [2] 43 b5 }

  condition:
    any of them
}