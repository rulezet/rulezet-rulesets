rule TTP_XOR_MULT_DOSStub_bf44 {
  strings:
    $key_bf44 = { eb 2c [2] 9f 34 [2] d8 36 [2] 9f 27 [2] d1 2b [2] dd 21 [2] ca 2a [2] d1 64 [2] ec }

  condition:
    any of them
}