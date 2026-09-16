rule TTP_XOR_QUAD_CurrentVersionRun_a5ca {
  strings:
    $key_a5ca = { f6 a5 [2] d2 ab [2] f9 87 [2] d7 a5 [2] c3 be [2] cc a4 [2] d2 b9 [2] d0 b8 [2] cb be [2] d7 b9 [2] cb 96 }

  condition:
    any of them
}