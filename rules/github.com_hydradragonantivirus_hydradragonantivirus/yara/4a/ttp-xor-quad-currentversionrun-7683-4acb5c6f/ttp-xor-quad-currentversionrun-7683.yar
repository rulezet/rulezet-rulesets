rule TTP_XOR_QUAD_CurrentVersionRun_7683 {
  strings:
    $key_7683 = { 25 ec [2] 01 e2 [2] 2a ce [2] 04 ec [2] 10 f7 [2] 1f ed [2] 01 f0 [2] 03 f1 [2] 18 f7 [2] 04 f0 [2] 18 df }

  condition:
    any of them
}