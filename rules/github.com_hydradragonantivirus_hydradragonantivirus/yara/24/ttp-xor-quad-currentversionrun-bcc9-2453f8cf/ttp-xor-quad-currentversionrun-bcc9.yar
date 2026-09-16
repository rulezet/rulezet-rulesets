rule TTP_XOR_QUAD_CurrentVersionRun_bcc9 {
  strings:
    $key_bcc9 = { ef a6 [2] cb a8 [2] e0 84 [2] ce a6 [2] da bd [2] d5 a7 [2] cb ba [2] c9 bb [2] d2 bd [2] ce ba [2] d2 95 }

  condition:
    any of them
}