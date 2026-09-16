rule TTP_XOR_MULT_DOSStub_bf19 {
  strings:
    $key_bf19 = { eb 71 [2] 9f 69 [2] d8 6b [2] 9f 7a [2] d1 76 [2] dd 7c [2] ca 77 [2] d1 39 [2] ec }

  condition:
    any of them
}