rule TTP_XOR_MULT_DOSStub_ca8e {
  strings:
    $key_ca8e = { 9e e6 [2] ea fe [2] ad fc [2] ea ed [2] a4 e1 [2] a8 eb [2] bf e0 [2] a4 ae [2] 99 }

  condition:
    any of them
}