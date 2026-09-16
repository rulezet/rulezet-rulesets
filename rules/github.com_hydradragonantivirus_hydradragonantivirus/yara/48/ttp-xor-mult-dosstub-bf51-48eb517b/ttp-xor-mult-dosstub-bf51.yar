rule TTP_XOR_MULT_DOSStub_bf51 {
  strings:
    $key_bf51 = { eb 39 [2] 9f 21 [2] d8 23 [2] 9f 32 [2] d1 3e [2] dd 34 [2] ca 3f [2] d1 71 [2] ec }

  condition:
    any of them
}