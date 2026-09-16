rule TTP_XOR_QUAD_CurrentVersionRun_0683 {
  strings:
    $key_0683 = { 55 ec [2] 71 e2 [2] 5a ce [2] 74 ec [2] 60 f7 [2] 6f ed [2] 71 f0 [2] 73 f1 [2] 68 f7 [2] 74 f0 [2] 68 df }

  condition:
    any of them
}