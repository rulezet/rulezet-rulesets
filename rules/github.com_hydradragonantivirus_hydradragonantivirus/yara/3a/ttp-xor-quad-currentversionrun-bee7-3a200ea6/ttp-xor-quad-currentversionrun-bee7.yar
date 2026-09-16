rule TTP_XOR_QUAD_CurrentVersionRun_bee7 {
  strings:
    $key_bee7 = { ed 88 [2] c9 86 [2] e2 aa [2] cc 88 [2] d8 93 [2] d7 89 [2] c9 94 [2] cb 95 [2] d0 93 [2] cc 94 [2] d0 bb }

  condition:
    any of them
}