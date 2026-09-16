rule TTP_XOR_QUAD_CurrentVersionRun_a20f {
  strings:
    $key_a20f = { f1 60 [2] d5 6e [2] fe 42 [2] d0 60 [2] c4 7b [2] cb 61 [2] d5 7c [2] d7 7d [2] cc 7b [2] d0 7c [2] cc 53 }

  condition:
    any of them
}