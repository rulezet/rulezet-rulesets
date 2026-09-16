rule TTP_XOR_QUAD_CurrentVersionRun_f797 {
  strings:
    $key_f797 = { a4 f8 [2] 80 f6 [2] ab da [2] 85 f8 [2] 91 e3 [2] 9e f9 [2] 80 e4 [2] 82 e5 [2] 99 e3 [2] 85 e4 [2] 99 cb }

  condition:
    any of them
}