rule TTP_XOR_QUAD_CurrentVersionRun_a226 {
  strings:
    $key_a226 = { f1 49 [2] d5 47 [2] fe 6b [2] d0 49 [2] c4 52 [2] cb 48 [2] d5 55 [2] d7 54 [2] cc 52 [2] d0 55 [2] cc 7a }

  condition:
    any of them
}