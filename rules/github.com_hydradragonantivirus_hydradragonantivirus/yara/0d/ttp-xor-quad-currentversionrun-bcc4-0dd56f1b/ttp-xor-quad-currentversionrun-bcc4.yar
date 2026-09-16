rule TTP_XOR_QUAD_CurrentVersionRun_bcc4 {
  strings:
    $key_bcc4 = { ef ab [2] cb a5 [2] e0 89 [2] ce ab [2] da b0 [2] d5 aa [2] cb b7 [2] c9 b6 [2] d2 b0 [2] ce b7 [2] d2 98 }

  condition:
    any of them
}