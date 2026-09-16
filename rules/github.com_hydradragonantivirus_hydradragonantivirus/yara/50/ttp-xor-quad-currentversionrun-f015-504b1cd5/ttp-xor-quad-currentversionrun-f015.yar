rule TTP_XOR_QUAD_CurrentVersionRun_f015 {
  strings:
    $key_f015 = { a3 7a [2] 87 74 [2] ac 58 [2] 82 7a [2] 96 61 [2] 99 7b [2] 87 66 [2] 85 67 [2] 9e 61 [2] 82 66 [2] 9e 49 }

  condition:
    any of them
}