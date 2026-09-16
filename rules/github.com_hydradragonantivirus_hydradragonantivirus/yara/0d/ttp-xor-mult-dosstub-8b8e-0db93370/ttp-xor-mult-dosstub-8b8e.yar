rule TTP_XOR_MULT_DOSStub_8b8e {
  strings:
    $key_8b8e = { df e6 [2] ab fe [2] ec fc [2] ab ed [2] e5 e1 [2] e9 eb [2] fe e0 [2] e5 ae [2] d8 }

  condition:
    any of them
}