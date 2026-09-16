rule TTP_XOR_QUAD_CurrentVersionRun_a502 {
  strings:
    $key_a502 = { f6 6d [2] d2 63 [2] f9 4f [2] d7 6d [2] c3 76 [2] cc 6c [2] d2 71 [2] d0 70 [2] cb 76 [2] d7 71 [2] cb 5e }

  condition:
    any of them
}