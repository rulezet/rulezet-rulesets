rule TTP_XOR_QUAD_CurrentVersionRun_2c83 {
  strings:
    $key_2c83 = { 7f ec [2] 5b e2 [2] 70 ce [2] 5e ec [2] 4a f7 [2] 45 ed [2] 5b f0 [2] 59 f1 [2] 42 f7 [2] 5e f0 [2] 42 df }

  condition:
    any of them
}