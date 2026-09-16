rule TTP_XOR_MULT_DOSStub_cbc0 {
  strings:
    $key_cbc0 = { 9f a8 [2] eb b0 [2] ac b2 [2] eb a3 [2] a5 af [2] a9 a5 [2] be ae [2] a5 e0 [2] 98 }

  condition:
    any of them
}