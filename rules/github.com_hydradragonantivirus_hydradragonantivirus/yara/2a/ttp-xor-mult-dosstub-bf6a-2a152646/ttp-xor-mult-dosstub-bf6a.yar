rule TTP_XOR_MULT_DOSStub_bf6a {
  strings:
    $key_bf6a = { eb 02 [2] 9f 1a [2] d8 18 [2] 9f 09 [2] d1 05 [2] dd 0f [2] ca 04 [2] d1 4a [2] ec }

  condition:
    any of them
}