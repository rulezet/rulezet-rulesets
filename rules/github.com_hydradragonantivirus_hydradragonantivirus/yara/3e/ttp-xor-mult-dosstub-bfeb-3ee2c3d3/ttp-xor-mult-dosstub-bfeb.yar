rule TTP_XOR_MULT_DOSStub_bfeb {
  strings:
    $key_bfeb = { eb 83 [2] 9f 9b [2] d8 99 [2] 9f 88 [2] d1 84 [2] dd 8e [2] ca 85 [2] d1 cb [2] ec }

  condition:
    any of them
}