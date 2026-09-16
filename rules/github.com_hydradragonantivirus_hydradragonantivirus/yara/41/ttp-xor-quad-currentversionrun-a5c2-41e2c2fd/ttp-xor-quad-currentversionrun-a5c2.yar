rule TTP_XOR_QUAD_CurrentVersionRun_a5c2 {
  strings:
    $key_a5c2 = { f6 ad [2] d2 a3 [2] f9 8f [2] d7 ad [2] c3 b6 [2] cc ac [2] d2 b1 [2] d0 b0 [2] cb b6 [2] d7 b1 [2] cb 9e }

  condition:
    any of them
}