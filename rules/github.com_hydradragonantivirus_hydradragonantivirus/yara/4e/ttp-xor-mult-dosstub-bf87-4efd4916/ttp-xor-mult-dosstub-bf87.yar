rule TTP_XOR_MULT_DOSStub_bf87 {
  strings:
    $key_bf87 = { eb ef [2] 9f f7 [2] d8 f5 [2] 9f e4 [2] d1 e8 [2] dd e2 [2] ca e9 [2] d1 a7 [2] ec }

  condition:
    any of them
}