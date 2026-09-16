rule TTP_XOR_MULT_DOSStub_cb97 {
  strings:
    $key_cb97 = { 9f ff [2] eb e7 [2] ac e5 [2] eb f4 [2] a5 f8 [2] a9 f2 [2] be f9 [2] a5 b7 [2] 98 }

  condition:
    any of them
}