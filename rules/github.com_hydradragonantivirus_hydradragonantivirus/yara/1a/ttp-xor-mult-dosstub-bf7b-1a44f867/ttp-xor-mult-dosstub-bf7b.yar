rule TTP_XOR_MULT_DOSStub_bf7b {
  strings:
    $key_bf7b = { eb 13 [2] 9f 0b [2] d8 09 [2] 9f 18 [2] d1 14 [2] dd 1e [2] ca 15 [2] d1 5b [2] ec }

  condition:
    any of them
}