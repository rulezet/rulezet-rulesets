rule TTP_XOR_MULT_DOSStub_cbc9 {
  strings:
    $key_cbc9 = { 9f a1 [2] eb b9 [2] ac bb [2] eb aa [2] a5 a6 [2] a9 ac [2] be a7 [2] a5 e9 [2] 98 }

  condition:
    any of them
}