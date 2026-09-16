rule TTP_XOR_QUAD_CurrentVersionRun_f083 {
  strings:
    $key_f083 = { a3 ec [2] 87 e2 [2] ac ce [2] 82 ec [2] 96 f7 [2] 99 ed [2] 87 f0 [2] 85 f1 [2] 9e f7 [2] 82 f0 [2] 9e df }

  condition:
    any of them
}