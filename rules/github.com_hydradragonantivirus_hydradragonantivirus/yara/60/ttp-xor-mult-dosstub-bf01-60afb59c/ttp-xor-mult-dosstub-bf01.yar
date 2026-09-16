rule TTP_XOR_MULT_DOSStub_bf01 {
  strings:
    $key_bf01 = { eb 69 [2] 9f 71 [2] d8 73 [2] 9f 62 [2] d1 6e [2] dd 64 [2] ca 6f [2] d1 21 [2] ec }

  condition:
    any of them
}