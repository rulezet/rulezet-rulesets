rule TTP_XOR_MULT_DOSStub_bf39 {
  strings:
    $key_bf39 = { eb 51 [2] 9f 49 [2] d8 4b [2] 9f 5a [2] d1 56 [2] dd 5c [2] ca 57 [2] d1 19 [2] ec }

  condition:
    any of them
}