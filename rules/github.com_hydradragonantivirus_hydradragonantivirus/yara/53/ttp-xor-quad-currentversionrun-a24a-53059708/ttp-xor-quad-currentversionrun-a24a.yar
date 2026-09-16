rule TTP_XOR_QUAD_CurrentVersionRun_a24a {
  strings:
    $key_a24a = { f1 25 [2] d5 2b [2] fe 07 [2] d0 25 [2] c4 3e [2] cb 24 [2] d5 39 [2] d7 38 [2] cc 3e [2] d0 39 [2] cc 16 }

  condition:
    any of them
}