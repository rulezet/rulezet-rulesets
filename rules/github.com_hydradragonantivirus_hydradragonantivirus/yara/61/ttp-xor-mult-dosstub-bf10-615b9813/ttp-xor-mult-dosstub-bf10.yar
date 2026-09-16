rule TTP_XOR_MULT_DOSStub_bf10 {
  strings:
    $key_bf10 = { eb 78 [2] 9f 60 [2] d8 62 [2] 9f 73 [2] d1 7f [2] dd 75 [2] ca 7e [2] d1 30 [2] ec }

  condition:
    any of them
}