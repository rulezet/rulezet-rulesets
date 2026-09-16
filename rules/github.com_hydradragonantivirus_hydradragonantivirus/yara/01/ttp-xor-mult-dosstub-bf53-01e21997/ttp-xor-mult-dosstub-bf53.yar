rule TTP_XOR_MULT_DOSStub_bf53 {
  strings:
    $key_bf53 = { eb 3b [2] 9f 23 [2] d8 21 [2] 9f 30 [2] d1 3c [2] dd 36 [2] ca 3d [2] d1 73 [2] ec }

  condition:
    any of them
}