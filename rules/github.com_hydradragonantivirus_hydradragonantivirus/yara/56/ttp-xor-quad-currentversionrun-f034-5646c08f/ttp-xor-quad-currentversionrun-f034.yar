rule TTP_XOR_QUAD_CurrentVersionRun_f034 {
  strings:
    $key_f034 = { a3 5b [2] 87 55 [2] ac 79 [2] 82 5b [2] 96 40 [2] 99 5a [2] 87 47 [2] 85 46 [2] 9e 40 [2] 82 47 [2] 9e 68 }

  condition:
    any of them
}