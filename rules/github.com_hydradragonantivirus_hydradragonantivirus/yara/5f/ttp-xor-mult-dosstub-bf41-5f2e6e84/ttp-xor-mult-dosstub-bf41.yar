rule TTP_XOR_MULT_DOSStub_bf41 {
  strings:
    $key_bf41 = { eb 29 [2] 9f 31 [2] d8 33 [2] 9f 22 [2] d1 2e [2] dd 24 [2] ca 2f [2] d1 61 [2] ec }

  condition:
    any of them
}