rule TTP_XOR_QUAD_CurrentVersionRun_a27f {
  strings:
    $key_a27f = { f1 10 [2] d5 1e [2] fe 32 [2] d0 10 [2] c4 0b [2] cb 11 [2] d5 0c [2] d7 0d [2] cc 0b [2] d0 0c [2] cc 23 }

  condition:
    any of them
}