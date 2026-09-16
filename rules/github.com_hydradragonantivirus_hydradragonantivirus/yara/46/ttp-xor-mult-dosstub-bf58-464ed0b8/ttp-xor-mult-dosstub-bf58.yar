rule TTP_XOR_MULT_DOSStub_bf58 {
  strings:
    $key_bf58 = { eb 30 [2] 9f 28 [2] d8 2a [2] 9f 3b [2] d1 37 [2] dd 3d [2] ca 36 [2] d1 78 [2] ec }

  condition:
    any of them
}