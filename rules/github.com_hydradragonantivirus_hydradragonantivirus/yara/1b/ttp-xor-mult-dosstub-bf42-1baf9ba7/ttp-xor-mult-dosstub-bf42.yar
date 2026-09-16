rule TTP_XOR_MULT_DOSStub_bf42 {
  strings:
    $key_bf42 = { eb 2a [2] 9f 32 [2] d8 30 [2] 9f 21 [2] d1 2d [2] dd 27 [2] ca 2c [2] d1 62 [2] ec }

  condition:
    any of them
}