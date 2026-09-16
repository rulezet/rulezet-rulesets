rule TTP_XOR_QUAD_CurrentVersionRun_a5c1 {
  strings:
    $key_a5c1 = { f6 ae [2] d2 a0 [2] f9 8c [2] d7 ae [2] c3 b5 [2] cc af [2] d2 b2 [2] d0 b3 [2] cb b5 [2] d7 b2 [2] cb 9d }

  condition:
    any of them
}