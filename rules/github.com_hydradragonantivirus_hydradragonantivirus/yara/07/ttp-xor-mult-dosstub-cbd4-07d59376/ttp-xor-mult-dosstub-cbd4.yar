rule TTP_XOR_MULT_DOSStub_cbd4 {
  strings:
    $key_cbd4 = { 9f bc [2] eb a4 [2] ac a6 [2] eb b7 [2] a5 bb [2] a9 b1 [2] be ba [2] a5 f4 [2] 98 }

  condition:
    any of them
}