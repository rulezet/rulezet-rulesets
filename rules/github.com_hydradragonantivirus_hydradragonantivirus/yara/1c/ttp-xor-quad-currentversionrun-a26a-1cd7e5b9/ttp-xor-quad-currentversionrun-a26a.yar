rule TTP_XOR_QUAD_CurrentVersionRun_a26a {
  strings:
    $key_a26a = { f1 05 [2] d5 0b [2] fe 27 [2] d0 05 [2] c4 1e [2] cb 04 [2] d5 19 [2] d7 18 [2] cc 1e [2] d0 19 [2] cc 36 }

  condition:
    any of them
}