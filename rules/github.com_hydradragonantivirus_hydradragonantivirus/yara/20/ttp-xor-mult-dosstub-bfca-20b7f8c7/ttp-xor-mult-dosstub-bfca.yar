rule TTP_XOR_MULT_DOSStub_bfca {
  strings:
    $key_bfca = { eb a2 [2] 9f ba [2] d8 b8 [2] 9f a9 [2] d1 a5 [2] dd af [2] ca a4 [2] d1 ea [2] ec }

  condition:
    any of them
}