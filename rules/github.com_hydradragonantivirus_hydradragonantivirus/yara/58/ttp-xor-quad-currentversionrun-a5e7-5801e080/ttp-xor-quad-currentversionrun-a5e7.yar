rule TTP_XOR_QUAD_CurrentVersionRun_a5e7 {
  strings:
    $key_a5e7 = { f6 88 [2] d2 86 [2] f9 aa [2] d7 88 [2] c3 93 [2] cc 89 [2] d2 94 [2] d0 95 [2] cb 93 [2] d7 94 [2] cb bb }

  condition:
    any of them
}