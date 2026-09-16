rule TTP_XOR_MULT_DOSStub_0b8e {
  strings:
    $key_0b8e = { 5f e6 [2] 2b fe [2] 6c fc [2] 2b ed [2] 65 e1 [2] 69 eb [2] 7e e0 [2] 65 ae [2] 58 }

  condition:
    any of them
}