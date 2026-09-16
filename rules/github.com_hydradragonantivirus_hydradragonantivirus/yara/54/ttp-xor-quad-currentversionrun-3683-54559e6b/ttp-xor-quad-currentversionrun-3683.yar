rule TTP_XOR_QUAD_CurrentVersionRun_3683 {
  strings:
    $key_3683 = { 65 ec [2] 41 e2 [2] 6a ce [2] 44 ec [2] 50 f7 [2] 5f ed [2] 41 f0 [2] 43 f1 [2] 58 f7 [2] 44 f0 [2] 58 df }

  condition:
    any of them
}