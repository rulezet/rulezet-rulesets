rule TTP_XOR_MULT_DOSStub_bf60 {
  strings:
    $key_bf60 = { eb 08 [2] 9f 10 [2] d8 12 [2] 9f 03 [2] d1 0f [2] dd 05 [2] ca 0e [2] d1 40 [2] ec }

  condition:
    any of them
}