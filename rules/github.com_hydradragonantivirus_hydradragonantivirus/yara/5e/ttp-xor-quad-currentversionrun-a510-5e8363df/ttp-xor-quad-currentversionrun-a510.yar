rule TTP_XOR_QUAD_CurrentVersionRun_a510 {
  strings:
    $key_a510 = { f6 7f [2] d2 71 [2] f9 5d [2] d7 7f [2] c3 64 [2] cc 7e [2] d2 63 [2] d0 62 [2] cb 64 [2] d7 63 [2] cb 4c }

  condition:
    any of them
}