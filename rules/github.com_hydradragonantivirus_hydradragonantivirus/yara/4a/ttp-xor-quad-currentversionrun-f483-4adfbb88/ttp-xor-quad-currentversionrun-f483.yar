rule TTP_XOR_QUAD_CurrentVersionRun_f483 {
  strings:
    $key_f483 = { a7 ec [2] 83 e2 [2] a8 ce [2] 86 ec [2] 92 f7 [2] 9d ed [2] 83 f0 [2] 81 f1 [2] 9a f7 [2] 86 f0 [2] 9a df }

  condition:
    any of them
}