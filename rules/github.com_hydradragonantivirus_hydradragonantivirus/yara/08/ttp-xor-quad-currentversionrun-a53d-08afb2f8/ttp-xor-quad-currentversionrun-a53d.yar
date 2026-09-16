rule TTP_XOR_QUAD_CurrentVersionRun_a53d {
  strings:
    $key_a53d = { f6 52 [2] d2 5c [2] f9 70 [2] d7 52 [2] c3 49 [2] cc 53 [2] d2 4e [2] d0 4f [2] cb 49 [2] d7 4e [2] cb 61 }

  condition:
    any of them
}