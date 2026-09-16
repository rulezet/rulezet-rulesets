rule TTP_XOR_MULT_DOSStub_bf52 {
  strings:
    $key_bf52 = { eb 3a [2] 9f 22 [2] d8 20 [2] 9f 31 [2] d1 3d [2] dd 37 [2] ca 3c [2] d1 72 [2] ec }

  condition:
    any of them
}