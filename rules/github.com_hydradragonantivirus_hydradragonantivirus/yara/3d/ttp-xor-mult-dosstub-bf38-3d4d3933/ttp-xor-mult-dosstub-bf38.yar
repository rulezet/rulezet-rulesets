rule TTP_XOR_MULT_DOSStub_bf38 {
  strings:
    $key_bf38 = { eb 50 [2] 9f 48 [2] d8 4a [2] 9f 5b [2] d1 57 [2] dd 5d [2] ca 56 [2] d1 18 [2] ec }

  condition:
    any of them
}