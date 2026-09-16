rule TTP_XOR_QUAD_CurrentVersionRun_08fa {
  strings:
    $key_08fa = { 5b 95 [2] 7f 9b [2] 54 b7 [2] 7a 95 [2] 6e 8e [2] 61 94 [2] 7f 89 [2] 7d 88 [2] 66 8e [2] 7a 89 [2] 66 a6 }

  condition:
    any of them
}