rule TTP_XOR_QUAD_CurrentVersionRun_a2ff {
  strings:
    $key_a2ff = { f1 90 [2] d5 9e [2] fe b2 [2] d0 90 [2] c4 8b [2] cb 91 [2] d5 8c [2] d7 8d [2] cc 8b [2] d0 8c [2] cc a3 }

  condition:
    any of them
}