rule TTP_XOR_QUAD_CurrentVersionRun_e083 {
  strings:
    $key_e083 = { b3 ec [2] 97 e2 [2] bc ce [2] 92 ec [2] 86 f7 [2] 89 ed [2] 97 f0 [2] 95 f1 [2] 8e f7 [2] 92 f0 [2] 8e df }

  condition:
    any of them
}