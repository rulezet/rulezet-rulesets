rule TTP_XOR_QUAD_CurrentVersionRun_a5d2 {
  strings:
    $key_a5d2 = { f6 bd [2] d2 b3 [2] f9 9f [2] d7 bd [2] c3 a6 [2] cc bc [2] d2 a1 [2] d0 a0 [2] cb a6 [2] d7 a1 [2] cb 8e }

  condition:
    any of them
}