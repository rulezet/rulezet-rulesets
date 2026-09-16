rule TTP_XOR_QUAD_CurrentVersionRun_b9d5 {
  strings:
    $key_b9d5 = { ea ba [2] ce b4 [2] e5 98 [2] cb ba [2] df a1 [2] d0 bb [2] ce a6 [2] cc a7 [2] d7 a1 [2] cb a6 [2] d7 89 }

  condition:
    any of them
}