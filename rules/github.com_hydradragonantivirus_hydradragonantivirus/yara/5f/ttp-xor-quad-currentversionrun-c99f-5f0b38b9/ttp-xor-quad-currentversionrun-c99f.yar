rule TTP_XOR_QUAD_CurrentVersionRun_c99f {
  strings:
    $key_c99f = { 9a f0 [2] be fe [2] 95 d2 [2] bb f0 [2] af eb [2] a0 f1 [2] be ec [2] bc ed [2] a7 eb [2] bb ec [2] a7 c3 }

  condition:
    any of them
}