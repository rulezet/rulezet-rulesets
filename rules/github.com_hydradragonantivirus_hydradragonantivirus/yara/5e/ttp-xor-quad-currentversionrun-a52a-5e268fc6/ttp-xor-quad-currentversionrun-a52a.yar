rule TTP_XOR_QUAD_CurrentVersionRun_a52a {
  strings:
    $key_a52a = { f6 45 [2] d2 4b [2] f9 67 [2] d7 45 [2] c3 5e [2] cc 44 [2] d2 59 [2] d0 58 [2] cb 5e [2] d7 59 [2] cb 76 }

  condition:
    any of them
}