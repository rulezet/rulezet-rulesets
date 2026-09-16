rule TTP_XOR_QUAD_CurrentVersionRun_3583 {
  strings:
    $key_3583 = { 66 ec [2] 42 e2 [2] 69 ce [2] 47 ec [2] 53 f7 [2] 5c ed [2] 42 f0 [2] 40 f1 [2] 5b f7 [2] 47 f0 [2] 5b df }

  condition:
    any of them
}