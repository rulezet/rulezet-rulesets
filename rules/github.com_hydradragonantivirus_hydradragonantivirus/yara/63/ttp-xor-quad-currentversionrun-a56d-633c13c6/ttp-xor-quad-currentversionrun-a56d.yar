rule TTP_XOR_QUAD_CurrentVersionRun_a56d {
  strings:
    $key_a56d = { f6 02 [2] d2 0c [2] f9 20 [2] d7 02 [2] c3 19 [2] cc 03 [2] d2 1e [2] d0 1f [2] cb 19 [2] d7 1e [2] cb 31 }

  condition:
    any of them
}