rule TTP_XOR_QUAD_CurrentVersionRun_c983 {
  strings:
    $key_c983 = { 9a ec [2] be e2 [2] 95 ce [2] bb ec [2] af f7 [2] a0 ed [2] be f0 [2] bc f1 [2] a7 f7 [2] bb f0 [2] a7 df }

  condition:
    any of them
}