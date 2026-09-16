rule TTP_XOR_MULT_DOSStub_bffc {
  strings:
    $key_bffc = { eb 94 [2] 9f 8c [2] d8 8e [2] 9f 9f [2] d1 93 [2] dd 99 [2] ca 92 [2] d1 dc [2] ec }

  condition:
    any of them
}