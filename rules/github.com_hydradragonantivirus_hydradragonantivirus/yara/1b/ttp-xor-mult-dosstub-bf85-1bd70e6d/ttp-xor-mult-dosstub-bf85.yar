rule TTP_XOR_MULT_DOSStub_bf85 {
  strings:
    $key_bf85 = { eb ed [2] 9f f5 [2] d8 f7 [2] 9f e6 [2] d1 ea [2] dd e0 [2] ca eb [2] d1 a5 [2] ec }

  condition:
    any of them
}