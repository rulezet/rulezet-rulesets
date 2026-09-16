rule TTP_XOR_MULT_DOSStub_bf66 {
  strings:
    $key_bf66 = { eb 0e [2] 9f 16 [2] d8 14 [2] 9f 05 [2] d1 09 [2] dd 03 [2] ca 08 [2] d1 46 [2] ec }

  condition:
    any of them
}