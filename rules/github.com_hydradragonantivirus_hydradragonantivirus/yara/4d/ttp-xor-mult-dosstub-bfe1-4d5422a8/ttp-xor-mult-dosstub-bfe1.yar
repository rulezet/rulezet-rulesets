rule TTP_XOR_MULT_DOSStub_bfe1 {
  strings:
    $key_bfe1 = { eb 89 [2] 9f 91 [2] d8 93 [2] 9f 82 [2] d1 8e [2] dd 84 [2] ca 8f [2] d1 c1 [2] ec }

  condition:
    any of them
}