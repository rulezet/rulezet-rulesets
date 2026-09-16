rule TTP_XOR_QUAD_CurrentVersionRun_a2fe {
  strings:
    $key_a2fe = { f1 91 [2] d5 9f [2] fe b3 [2] d0 91 [2] c4 8a [2] cb 90 [2] d5 8d [2] d7 8c [2] cc 8a [2] d0 8d [2] cc a2 }

  condition:
    any of them
}