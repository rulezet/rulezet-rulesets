rule TTP_XOR_MULT_DOSStub_cbd5 {
  strings:
    $key_cbd5 = { 9f bd [2] eb a5 [2] ac a7 [2] eb b6 [2] a5 ba [2] a9 b0 [2] be bb [2] a5 f5 [2] 98 }

  condition:
    any of them
}