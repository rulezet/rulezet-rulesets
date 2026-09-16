rule TTP_XOR_MULT_DOSStub_bff9 {
  strings:
    $key_bff9 = { eb 91 [2] 9f 89 [2] d8 8b [2] 9f 9a [2] d1 96 [2] dd 9c [2] ca 97 [2] d1 d9 [2] ec }

  condition:
    any of them
}