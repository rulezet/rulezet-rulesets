rule TTP_XOR_MULT_DOSStub_cbd1 {
  strings:
    $key_cbd1 = { 9f b9 [2] eb a1 [2] ac a3 [2] eb b2 [2] a5 be [2] a9 b4 [2] be bf [2] a5 f1 [2] 98 }

  condition:
    any of them
}