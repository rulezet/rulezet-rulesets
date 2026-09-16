rule TTP_XOR_QUAD_CurrentVersionRun_a232 {
  strings:
    $key_a232 = { f1 5d [2] d5 53 [2] fe 7f [2] d0 5d [2] c4 46 [2] cb 5c [2] d5 41 [2] d7 40 [2] cc 46 [2] d0 41 [2] cc 6e }

  condition:
    any of them
}