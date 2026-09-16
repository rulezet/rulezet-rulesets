rule TTP_XOR_MULT_DOSStub_cb84 {
  strings:
    $key_cb84 = { 9f ec [2] eb f4 [2] ac f6 [2] eb e7 [2] a5 eb [2] a9 e1 [2] be ea [2] a5 a4 [2] 98 }

  condition:
    any of them
}