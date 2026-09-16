rule TTP_XOR_MULT_DOSStub_bf5e {
  strings:
    $key_bf5e = { eb 36 [2] 9f 2e [2] d8 2c [2] 9f 3d [2] d1 31 [2] dd 3b [2] ca 30 [2] d1 7e [2] ec }

  condition:
    any of them
}