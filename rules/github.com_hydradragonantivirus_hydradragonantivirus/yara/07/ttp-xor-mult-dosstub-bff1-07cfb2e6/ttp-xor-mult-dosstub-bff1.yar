rule TTP_XOR_MULT_DOSStub_bff1 {
  strings:
    $key_bff1 = { eb 99 [2] 9f 81 [2] d8 83 [2] 9f 92 [2] d1 9e [2] dd 94 [2] ca 9f [2] d1 d1 [2] ec }

  condition:
    any of them
}