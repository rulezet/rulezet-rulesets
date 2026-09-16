rule TTP_XOR_MULT_DOSStub_cbd7 {
  strings:
    $key_cbd7 = { 9f bf [2] eb a7 [2] ac a5 [2] eb b4 [2] a5 b8 [2] a9 b2 [2] be b9 [2] a5 f7 [2] 98 }

  condition:
    any of them
}