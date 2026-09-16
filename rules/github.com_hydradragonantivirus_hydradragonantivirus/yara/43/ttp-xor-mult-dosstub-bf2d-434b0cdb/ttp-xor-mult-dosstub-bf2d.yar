rule TTP_XOR_MULT_DOSStub_bf2d {
  strings:
    $key_bf2d = { eb 45 [2] 9f 5d [2] d8 5f [2] 9f 4e [2] d1 42 [2] dd 48 [2] ca 43 [2] d1 0d [2] ec }

  condition:
    any of them
}