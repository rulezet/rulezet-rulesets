rule TTP_XOR_QUAD_CurrentVersionRun_f078 {
  strings:
    $key_f078 = { a3 17 [2] 87 19 [2] ac 35 [2] 82 17 [2] 96 0c [2] 99 16 [2] 87 0b [2] 85 0a [2] 9e 0c [2] 82 0b [2] 9e 24 }

  condition:
    any of them
}