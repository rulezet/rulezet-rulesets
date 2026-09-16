rule TTP_XOR_MULT_DOSStub_bf2c {
  strings:
    $key_bf2c = { eb 44 [2] 9f 5c [2] d8 5e [2] 9f 4f [2] d1 43 [2] dd 49 [2] ca 42 [2] d1 0c [2] ec }

  condition:
    any of them
}