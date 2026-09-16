rule TTP_XOR_MULT_DOSStub_bfcb {
  strings:
    $key_bfcb = { eb a3 [2] 9f bb [2] d8 b9 [2] 9f a8 [2] d1 a4 [2] dd ae [2] ca a5 [2] d1 eb [2] ec }

  condition:
    any of them
}