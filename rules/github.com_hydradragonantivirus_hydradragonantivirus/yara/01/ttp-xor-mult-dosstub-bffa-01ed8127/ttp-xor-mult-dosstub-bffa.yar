rule TTP_XOR_MULT_DOSStub_bffa {
  strings:
    $key_bffa = { eb 92 [2] 9f 8a [2] d8 88 [2] 9f 99 [2] d1 95 [2] dd 9f [2] ca 94 [2] d1 da [2] ec }

  condition:
    any of them
}