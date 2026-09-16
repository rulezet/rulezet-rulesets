rule TTP_XOR_MULT_DOSStub_bfc1 {
  strings:
    $key_bfc1 = { eb a9 [2] 9f b1 [2] d8 b3 [2] 9f a2 [2] d1 ae [2] dd a4 [2] ca af [2] d1 e1 [2] ec }

  condition:
    any of them
}