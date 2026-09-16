rule TTP_XOR_QUAD_CurrentVersionRun_a551 {
  strings:
    $key_a551 = { f6 3e [2] d2 30 [2] f9 1c [2] d7 3e [2] c3 25 [2] cc 3f [2] d2 22 [2] d0 23 [2] cb 25 [2] d7 22 [2] cb 0d }

  condition:
    any of them
}