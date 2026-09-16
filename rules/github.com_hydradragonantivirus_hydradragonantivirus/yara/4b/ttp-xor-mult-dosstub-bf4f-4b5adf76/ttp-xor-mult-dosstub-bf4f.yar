rule TTP_XOR_MULT_DOSStub_bf4f {
  strings:
    $key_bf4f = { eb 27 [2] 9f 3f [2] d8 3d [2] 9f 2c [2] d1 20 [2] dd 2a [2] ca 21 [2] d1 6f [2] ec }

  condition:
    any of them
}