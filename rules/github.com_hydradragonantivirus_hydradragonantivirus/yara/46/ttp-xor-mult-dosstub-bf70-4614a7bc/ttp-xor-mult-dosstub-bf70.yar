rule TTP_XOR_MULT_DOSStub_bf70 {
  strings:
    $key_bf70 = { eb 18 [2] 9f 00 [2] d8 02 [2] 9f 13 [2] d1 1f [2] dd 15 [2] ca 1e [2] d1 50 [2] ec }

  condition:
    any of them
}