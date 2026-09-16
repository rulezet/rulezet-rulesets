rule TTP_XOR_MULT_DOSStub_008e {
  strings:
    $key_008e = { 54 e6 [2] 20 fe [2] 67 fc [2] 20 ed [2] 6e e1 [2] 62 eb [2] 75 e0 [2] 6e ae [2] 53 }

  condition:
    any of them
}