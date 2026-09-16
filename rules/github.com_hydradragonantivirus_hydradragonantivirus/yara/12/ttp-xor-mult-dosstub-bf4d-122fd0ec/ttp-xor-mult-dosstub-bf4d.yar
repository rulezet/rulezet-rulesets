rule TTP_XOR_MULT_DOSStub_bf4d {
  strings:
    $key_bf4d = { eb 25 [2] 9f 3d [2] d8 3f [2] 9f 2e [2] d1 22 [2] dd 28 [2] ca 23 [2] d1 6d [2] ec }

  condition:
    any of them
}