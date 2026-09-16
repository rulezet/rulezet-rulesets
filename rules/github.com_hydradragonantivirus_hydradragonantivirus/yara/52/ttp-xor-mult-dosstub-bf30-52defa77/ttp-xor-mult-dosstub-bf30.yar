rule TTP_XOR_MULT_DOSStub_bf30 {
  strings:
    $key_bf30 = { eb 58 [2] 9f 40 [2] d8 42 [2] 9f 53 [2] d1 5f [2] dd 55 [2] ca 5e [2] d1 10 [2] ec }

  condition:
    any of them
}