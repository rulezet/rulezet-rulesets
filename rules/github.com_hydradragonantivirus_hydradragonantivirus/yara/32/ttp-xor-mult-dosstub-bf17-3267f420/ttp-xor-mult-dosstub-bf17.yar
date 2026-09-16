rule TTP_XOR_MULT_DOSStub_bf17 {
  strings:
    $key_bf17 = { eb 7f [2] 9f 67 [2] d8 65 [2] 9f 74 [2] d1 78 [2] dd 72 [2] ca 79 [2] d1 37 [2] ec }

  condition:
    any of them
}