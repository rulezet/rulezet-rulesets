rule TTP_XOR_QUAD_CurrentVersionRun_d983 {
  strings:
    $key_d983 = { 8a ec [2] ae e2 [2] 85 ce [2] ab ec [2] bf f7 [2] b0 ed [2] ae f0 [2] ac f1 [2] b7 f7 [2] ab f0 [2] b7 df }

  condition:
    any of them
}