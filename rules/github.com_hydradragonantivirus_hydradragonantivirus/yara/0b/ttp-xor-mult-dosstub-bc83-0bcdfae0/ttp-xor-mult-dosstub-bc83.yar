rule TTP_XOR_MULT_DOSStub_bc83 {
  strings:
    $key_bc83 = { e8 eb [2] 9c f3 [2] db f1 [2] 9c e0 [2] d2 ec [2] de e6 [2] c9 ed [2] d2 a3 [2] ef }

  condition:
    any of them
}