rule TTP_XOR_MULT_DOSStub_bf05 {
  strings:
    $key_bf05 = { eb 6d [2] 9f 75 [2] d8 77 [2] 9f 66 [2] d1 6a [2] dd 60 [2] ca 6b [2] d1 25 [2] ec }

  condition:
    any of them
}