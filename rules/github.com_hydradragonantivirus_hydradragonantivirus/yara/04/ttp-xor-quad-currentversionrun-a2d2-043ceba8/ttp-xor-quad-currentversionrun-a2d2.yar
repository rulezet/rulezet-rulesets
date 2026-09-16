rule TTP_XOR_QUAD_CurrentVersionRun_a2d2 {
  strings:
    $key_a2d2 = { f1 bd [2] d5 b3 [2] fe 9f [2] d0 bd [2] c4 a6 [2] cb bc [2] d5 a1 [2] d7 a0 [2] cc a6 [2] d0 a1 [2] cc 8e }

  condition:
    any of them
}