rule TTP_XOR_QUAD_CurrentVersionRun_a21f {
  strings:
    $key_a21f = { f1 70 [2] d5 7e [2] fe 52 [2] d0 70 [2] c4 6b [2] cb 71 [2] d5 6c [2] d7 6d [2] cc 6b [2] d0 6c [2] cc 43 }

  condition:
    any of them
}