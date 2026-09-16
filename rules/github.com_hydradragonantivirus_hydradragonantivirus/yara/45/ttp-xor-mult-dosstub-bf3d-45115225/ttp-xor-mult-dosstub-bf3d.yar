rule TTP_XOR_MULT_DOSStub_bf3d {
  strings:
    $key_bf3d = { eb 55 [2] 9f 4d [2] d8 4f [2] 9f 5e [2] d1 52 [2] dd 58 [2] ca 53 [2] d1 1d [2] ec }

  condition:
    any of them
}