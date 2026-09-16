rule TTP_XOR_QUAD_CurrentVersionRun_a228 {
  strings:
    $key_a228 = { f1 47 [2] d5 49 [2] fe 65 [2] d0 47 [2] c4 5c [2] cb 46 [2] d5 5b [2] d7 5a [2] cc 5c [2] d0 5b [2] cc 74 }

  condition:
    any of them
}