rule TTP_XOR_MULT_DOSStub_bf08 {
  strings:
    $key_bf08 = { eb 60 [2] 9f 78 [2] d8 7a [2] 9f 6b [2] d1 67 [2] dd 6d [2] ca 66 [2] d1 28 [2] ec }

  condition:
    any of them
}