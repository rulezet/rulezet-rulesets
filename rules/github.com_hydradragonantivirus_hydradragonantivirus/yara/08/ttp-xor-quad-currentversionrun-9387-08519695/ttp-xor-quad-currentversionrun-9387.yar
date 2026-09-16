rule TTP_XOR_QUAD_CurrentVersionRun_9387 {
  strings:
    $key_9387 = { c0 e8 [2] e4 e6 [2] cf ca [2] e1 e8 [2] f5 f3 [2] fa e9 [2] e4 f4 [2] e6 f5 [2] fd f3 [2] e1 f4 [2] fd db }

  condition:
    any of them
}