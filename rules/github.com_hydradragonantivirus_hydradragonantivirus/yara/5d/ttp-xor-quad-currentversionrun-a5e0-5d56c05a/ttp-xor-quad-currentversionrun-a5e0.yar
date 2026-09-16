rule TTP_XOR_QUAD_CurrentVersionRun_a5e0 {
  strings:
    $key_a5e0 = { f6 8f [2] d2 81 [2] f9 ad [2] d7 8f [2] c3 94 [2] cc 8e [2] d2 93 [2] d0 92 [2] cb 94 [2] d7 93 [2] cb bc }

  condition:
    any of them
}