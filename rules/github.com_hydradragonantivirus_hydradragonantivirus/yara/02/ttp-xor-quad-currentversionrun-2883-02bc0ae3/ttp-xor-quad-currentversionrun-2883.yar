rule TTP_XOR_QUAD_CurrentVersionRun_2883 {
  strings:
    $key_2883 = { 7b ec [2] 5f e2 [2] 74 ce [2] 5a ec [2] 4e f7 [2] 41 ed [2] 5f f0 [2] 5d f1 [2] 46 f7 [2] 5a f0 [2] 46 df }

  condition:
    any of them
}