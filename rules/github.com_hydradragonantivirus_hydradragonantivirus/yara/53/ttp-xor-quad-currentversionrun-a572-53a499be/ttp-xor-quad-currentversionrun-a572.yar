rule TTP_XOR_QUAD_CurrentVersionRun_a572 {
  strings:
    $key_a572 = { f6 1d [2] d2 13 [2] f9 3f [2] d7 1d [2] c3 06 [2] cc 1c [2] d2 01 [2] d0 00 [2] cb 06 [2] d7 01 [2] cb 2e }

  condition:
    any of them
}