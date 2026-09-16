rule TTP_XOR_MULT_DOSStub_bf5c {
  strings:
    $key_bf5c = { eb 34 [2] 9f 2c [2] d8 2e [2] 9f 3f [2] d1 33 [2] dd 39 [2] ca 32 [2] d1 7c [2] ec }

  condition:
    any of them
}