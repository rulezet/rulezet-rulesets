rule TTP_XOR_QUAD_CurrentVersionRun_a5f0 {
  strings:
    $key_a5f0 = { f6 9f [2] d2 91 [2] f9 bd [2] d7 9f [2] c3 84 [2] cc 9e [2] d2 83 [2] d0 82 [2] cb 84 [2] d7 83 [2] cb ac }

  condition:
    any of them
}