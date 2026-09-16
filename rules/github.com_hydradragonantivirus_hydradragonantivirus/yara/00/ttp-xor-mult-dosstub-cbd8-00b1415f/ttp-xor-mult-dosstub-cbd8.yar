rule TTP_XOR_MULT_DOSStub_cbd8 {
  strings:
    $key_cbd8 = { 9f b0 [2] eb a8 [2] ac aa [2] eb bb [2] a5 b7 [2] a9 bd [2] be b6 [2] a5 f8 [2] 98 }

  condition:
    any of them
}