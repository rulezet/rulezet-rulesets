rule TTP_XOR_QUAD_CurrentVersionRun_a23c {
  strings:
    $key_a23c = { f1 53 [2] d5 5d [2] fe 71 [2] d0 53 [2] c4 48 [2] cb 52 [2] d5 4f [2] d7 4e [2] cc 48 [2] d0 4f [2] cc 60 }

  condition:
    any of them
}