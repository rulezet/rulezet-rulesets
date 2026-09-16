rule TTP_XOR_MULT_DOSStub_bf29 {
  strings:
    $key_bf29 = { eb 41 [2] 9f 59 [2] d8 5b [2] 9f 4a [2] d1 46 [2] dd 4c [2] ca 47 [2] d1 09 [2] ec }

  condition:
    any of them
}