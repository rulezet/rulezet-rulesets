rule TTP_XOR_MULT_DOSStub_bf7d {
  strings:
    $key_bf7d = { eb 15 [2] 9f 0d [2] d8 0f [2] 9f 1e [2] d1 12 [2] dd 18 [2] ca 13 [2] d1 5d [2] ec }

  condition:
    any of them
}