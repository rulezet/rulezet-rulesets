rule TTP_XOR_QUAD_CurrentVersionRun_f054 {
  strings:
    $key_f054 = { a3 3b [2] 87 35 [2] ac 19 [2] 82 3b [2] 96 20 [2] 99 3a [2] 87 27 [2] 85 26 [2] 9e 20 [2] 82 27 [2] 9e 08 }

  condition:
    any of them
}