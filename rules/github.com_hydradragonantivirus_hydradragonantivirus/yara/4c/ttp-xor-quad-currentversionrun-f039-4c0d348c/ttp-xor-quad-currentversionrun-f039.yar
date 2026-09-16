rule TTP_XOR_QUAD_CurrentVersionRun_f039 {
  strings:
    $key_f039 = { a3 56 [2] 87 58 [2] ac 74 [2] 82 56 [2] 96 4d [2] 99 57 [2] 87 4a [2] 85 4b [2] 9e 4d [2] 82 4a [2] 9e 65 }

  condition:
    any of them
}