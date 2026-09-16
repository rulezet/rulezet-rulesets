rule TTP_XOR_QUAD_CurrentVersionRun_f534 {
  strings:
    $key_f534 = { a6 5b [2] 82 55 [2] a9 79 [2] 87 5b [2] 93 40 [2] 9c 5a [2] 82 47 [2] 80 46 [2] 9b 40 [2] 87 47 [2] 9b 68 }

  condition:
    any of them
}