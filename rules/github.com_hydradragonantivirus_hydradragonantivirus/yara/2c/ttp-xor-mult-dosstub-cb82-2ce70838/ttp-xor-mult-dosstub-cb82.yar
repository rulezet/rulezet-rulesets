rule TTP_XOR_MULT_DOSStub_cb82 {
  strings:
    $key_cb82 = { 9f ea [2] eb f2 [2] ac f0 [2] eb e1 [2] a5 ed [2] a9 e7 [2] be ec [2] a5 a2 [2] 98 }

  condition:
    any of them
}