rule TTP_XOR_MULT_DOSStub_cbc2 {
  strings:
    $key_cbc2 = { 9f aa [2] eb b2 [2] ac b0 [2] eb a1 [2] a5 ad [2] a9 a7 [2] be ac [2] a5 e2 [2] 98 }

  condition:
    any of them
}