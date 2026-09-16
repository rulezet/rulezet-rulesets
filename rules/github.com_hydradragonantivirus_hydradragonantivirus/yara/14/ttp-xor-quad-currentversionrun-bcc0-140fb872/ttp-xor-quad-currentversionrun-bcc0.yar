rule TTP_XOR_QUAD_CurrentVersionRun_bcc0 {
  strings:
    $key_bcc0 = { ef af [2] cb a1 [2] e0 8d [2] ce af [2] da b4 [2] d5 ae [2] cb b3 [2] c9 b2 [2] d2 b4 [2] ce b3 [2] d2 9c }

  condition:
    any of them
}