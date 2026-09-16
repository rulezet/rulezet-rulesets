rule TTP_XOR_MULT_DOSStub_bf90 {
  strings:
    $key_bf90 = { eb f8 [2] 9f e0 [2] d8 e2 [2] 9f f3 [2] d1 ff [2] dd f5 [2] ca fe [2] d1 b0 [2] ec }

  condition:
    any of them
}