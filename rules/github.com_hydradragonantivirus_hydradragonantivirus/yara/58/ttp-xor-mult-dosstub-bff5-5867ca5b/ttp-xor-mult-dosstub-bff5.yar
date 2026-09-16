rule TTP_XOR_MULT_DOSStub_bff5 {
  strings:
    $key_bff5 = { eb 9d [2] 9f 85 [2] d8 87 [2] 9f 96 [2] d1 9a [2] dd 90 [2] ca 9b [2] d1 d5 [2] ec }

  condition:
    any of them
}