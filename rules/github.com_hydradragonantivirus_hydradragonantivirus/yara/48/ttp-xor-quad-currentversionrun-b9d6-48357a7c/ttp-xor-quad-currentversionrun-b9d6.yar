rule TTP_XOR_QUAD_CurrentVersionRun_b9d6 {
  strings:
    $key_b9d6 = { ea b9 [2] ce b7 [2] e5 9b [2] cb b9 [2] df a2 [2] d0 b8 [2] ce a5 [2] cc a4 [2] d7 a2 [2] cb a5 [2] d7 8a }

  condition:
    any of them
}