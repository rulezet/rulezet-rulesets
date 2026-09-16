rule TTP_XOR_MULT_DOSStub_bfe7 {
  strings:
    $key_bfe7 = { eb 8f [2] 9f 97 [2] d8 95 [2] 9f 84 [2] d1 88 [2] dd 82 [2] ca 89 [2] d1 c7 [2] ec }

  condition:
    any of them
}