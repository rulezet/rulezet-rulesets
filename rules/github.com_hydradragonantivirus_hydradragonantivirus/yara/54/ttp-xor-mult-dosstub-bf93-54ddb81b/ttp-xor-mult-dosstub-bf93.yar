rule TTP_XOR_MULT_DOSStub_bf93 {
  strings:
    $key_bf93 = { eb fb [2] 9f e3 [2] d8 e1 [2] 9f f0 [2] d1 fc [2] dd f6 [2] ca fd [2] d1 b3 [2] ec }

  condition:
    any of them
}