rule TTP_XOR_QUAD_CurrentVersionRun_a505 {
  strings:
    $key_a505 = { f6 6a [2] d2 64 [2] f9 48 [2] d7 6a [2] c3 71 [2] cc 6b [2] d2 76 [2] d0 77 [2] cb 71 [2] d7 76 [2] cb 59 }

  condition:
    any of them
}