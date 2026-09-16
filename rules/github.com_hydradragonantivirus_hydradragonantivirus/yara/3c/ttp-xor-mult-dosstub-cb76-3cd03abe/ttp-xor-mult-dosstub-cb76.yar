rule TTP_XOR_MULT_DOSStub_cb76 {
  strings:
    $key_cb76 = { 9f 1e [2] eb 06 [2] ac 04 [2] eb 15 [2] a5 19 [2] a9 13 [2] be 18 [2] a5 56 [2] 98 }

  condition:
    any of them
}