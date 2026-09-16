rule TTP_XOR_QUAD_CurrentVersionRun_a2e7 {
  strings:
    $key_a2e7 = { f1 88 [2] d5 86 [2] fe aa [2] d0 88 [2] c4 93 [2] cb 89 [2] d5 94 [2] d7 95 [2] cc 93 [2] d0 94 [2] cc bb }

  condition:
    any of them
}