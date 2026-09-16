rule TTP_XOR_MULT_DOSStub_bf63 {
  strings:
    $key_bf63 = { eb 0b [2] 9f 13 [2] d8 11 [2] 9f 00 [2] d1 0c [2] dd 06 [2] ca 0d [2] d1 43 [2] ec }

  condition:
    any of them
}