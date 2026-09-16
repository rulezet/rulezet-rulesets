rule TTP_XOR_MULT_DOSStub_bf18 {
  strings:
    $key_bf18 = { eb 70 [2] 9f 68 [2] d8 6a [2] 9f 7b [2] d1 77 [2] dd 7d [2] ca 76 [2] d1 38 [2] ec }

  condition:
    any of them
}