rule TTP_XOR_MULT_DOSStub_cbc7 {
  strings:
    $key_cbc7 = { 9f af [2] eb b7 [2] ac b5 [2] eb a4 [2] a5 a8 [2] a9 a2 [2] be a9 [2] a5 e7 [2] 98 }

  condition:
    any of them
}