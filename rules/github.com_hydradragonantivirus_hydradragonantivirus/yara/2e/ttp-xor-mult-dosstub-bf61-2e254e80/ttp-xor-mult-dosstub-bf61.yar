rule TTP_XOR_MULT_DOSStub_bf61 {
  strings:
    $key_bf61 = { eb 09 [2] 9f 11 [2] d8 13 [2] 9f 02 [2] d1 0e [2] dd 04 [2] ca 0f [2] d1 41 [2] ec }

  condition:
    any of them
}