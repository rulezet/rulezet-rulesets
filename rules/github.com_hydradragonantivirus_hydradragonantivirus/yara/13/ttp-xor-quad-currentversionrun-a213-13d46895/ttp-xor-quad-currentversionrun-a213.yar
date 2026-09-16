rule TTP_XOR_QUAD_CurrentVersionRun_a213 {
  strings:
    $key_a213 = { f1 7c [2] d5 72 [2] fe 5e [2] d0 7c [2] c4 67 [2] cb 7d [2] d5 60 [2] d7 61 [2] cc 67 [2] d0 60 [2] cc 4f }

  condition:
    any of them
}