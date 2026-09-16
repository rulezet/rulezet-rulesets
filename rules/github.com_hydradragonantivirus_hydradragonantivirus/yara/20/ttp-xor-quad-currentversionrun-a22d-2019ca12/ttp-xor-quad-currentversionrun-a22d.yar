rule TTP_XOR_QUAD_CurrentVersionRun_a22d {
  strings:
    $key_a22d = { f1 42 [2] d5 4c [2] fe 60 [2] d0 42 [2] c4 59 [2] cb 43 [2] d5 5e [2] d7 5f [2] cc 59 [2] d0 5e [2] cc 71 }

  condition:
    any of them
}