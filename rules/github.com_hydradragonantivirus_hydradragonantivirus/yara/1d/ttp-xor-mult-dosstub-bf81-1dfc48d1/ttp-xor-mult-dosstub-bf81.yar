rule TTP_XOR_MULT_DOSStub_bf81 {
  strings:
    $key_bf81 = { eb e9 [2] 9f f1 [2] d8 f3 [2] 9f e2 [2] d1 ee [2] dd e4 [2] ca ef [2] d1 a1 [2] ec }

  condition:
    any of them
}