rule TTP_XOR_QUAD_CurrentVersionRun_f037 {
  strings:
    $key_f037 = { a3 58 [2] 87 56 [2] ac 7a [2] 82 58 [2] 96 43 [2] 99 59 [2] 87 44 [2] 85 45 [2] 9e 43 [2] 82 44 [2] 9e 6b }

  condition:
    any of them
}