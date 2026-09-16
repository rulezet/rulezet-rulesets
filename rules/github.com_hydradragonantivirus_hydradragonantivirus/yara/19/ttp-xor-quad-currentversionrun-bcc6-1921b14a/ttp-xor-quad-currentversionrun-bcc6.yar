rule TTP_XOR_QUAD_CurrentVersionRun_bcc6 {
  strings:
    $key_bcc6 = { ef a9 [2] cb a7 [2] e0 8b [2] ce a9 [2] da b2 [2] d5 a8 [2] cb b5 [2] c9 b4 [2] d2 b2 [2] ce b5 [2] d2 9a }

  condition:
    any of them
}