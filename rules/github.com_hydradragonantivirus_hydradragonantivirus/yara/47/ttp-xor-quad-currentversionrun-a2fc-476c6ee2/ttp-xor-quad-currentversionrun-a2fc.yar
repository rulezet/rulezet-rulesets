rule TTP_XOR_QUAD_CurrentVersionRun_a2fc {
  strings:
    $key_a2fc = { f1 93 [2] d5 9d [2] fe b1 [2] d0 93 [2] c4 88 [2] cb 92 [2] d5 8f [2] d7 8e [2] cc 88 [2] d0 8f [2] cc a0 }

  condition:
    any of them
}