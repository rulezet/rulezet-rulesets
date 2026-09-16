rule TTP_XOR_MULT_DOSStub_bf86 {
  strings:
    $key_bf86 = { eb ee [2] 9f f6 [2] d8 f4 [2] 9f e5 [2] d1 e9 [2] dd e3 [2] ca e8 [2] d1 a6 [2] ec }

  condition:
    any of them
}