rule TTP_XOR_QUAD_CurrentVersionRun_bcc5 {
  strings:
    $key_bcc5 = { ef aa [2] cb a4 [2] e0 88 [2] ce aa [2] da b1 [2] d5 ab [2] cb b6 [2] c9 b7 [2] d2 b1 [2] ce b6 [2] d2 99 }

  condition:
    any of them
}