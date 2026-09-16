rule TTP_XOR_MULT_DOSStub_bf27 {
  strings:
    $key_bf27 = { eb 4f [2] 9f 57 [2] d8 55 [2] 9f 44 [2] d1 48 [2] dd 42 [2] ca 49 [2] d1 07 [2] ec }

  condition:
    any of them
}