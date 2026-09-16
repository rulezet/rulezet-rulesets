rule TTP_XOR_MULT_DOSStub_bf0c {
  strings:
    $key_bf0c = { eb 64 [2] 9f 7c [2] d8 7e [2] 9f 6f [2] d1 63 [2] dd 69 [2] ca 62 [2] d1 2c [2] ec }

  condition:
    any of them
}