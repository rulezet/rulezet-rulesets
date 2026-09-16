rule TTP_XOR_MULT_DOSStub_cb85 {
  strings:
    $key_cb85 = { 9f ed [2] eb f5 [2] ac f7 [2] eb e6 [2] a5 ea [2] a9 e0 [2] be eb [2] a5 a5 [2] 98 }

  condition:
    any of them
}