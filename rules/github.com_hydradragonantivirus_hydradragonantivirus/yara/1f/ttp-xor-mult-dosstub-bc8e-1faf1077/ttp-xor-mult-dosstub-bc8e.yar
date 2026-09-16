rule TTP_XOR_MULT_DOSStub_bc8e {
  strings:
    $key_bc8e = { e8 e6 [2] 9c fe [2] db fc [2] 9c ed [2] d2 e1 [2] de eb [2] c9 e0 [2] d2 ae [2] ef }

  condition:
    any of them
}