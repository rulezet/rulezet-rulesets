rule TTP_XOR_MULT_DOSStub_bf5d {
  strings:
    $key_bf5d = { eb 35 [2] 9f 2d [2] d8 2f [2] 9f 3e [2] d1 32 [2] dd 38 [2] ca 33 [2] d1 7d [2] ec }

  condition:
    any of them
}