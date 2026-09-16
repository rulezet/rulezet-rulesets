rule TTP_XOR_MULT_DOSStub_bf89 {
  strings:
    $key_bf89 = { eb e1 [2] 9f f9 [2] d8 fb [2] 9f ea [2] d1 e6 [2] dd ec [2] ca e7 [2] d1 a9 [2] ec }

  condition:
    any of them
}