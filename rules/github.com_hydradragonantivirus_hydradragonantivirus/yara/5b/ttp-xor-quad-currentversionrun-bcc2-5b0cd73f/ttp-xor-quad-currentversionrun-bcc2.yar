rule TTP_XOR_QUAD_CurrentVersionRun_bcc2 {
  strings:
    $key_bcc2 = { ef ad [2] cb a3 [2] e0 8f [2] ce ad [2] da b6 [2] d5 ac [2] cb b1 [2] c9 b0 [2] d2 b6 [2] ce b1 [2] d2 9e }

  condition:
    any of them
}