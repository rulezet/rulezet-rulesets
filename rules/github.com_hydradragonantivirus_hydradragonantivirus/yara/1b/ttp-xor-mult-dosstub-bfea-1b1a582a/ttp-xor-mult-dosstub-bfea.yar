rule TTP_XOR_MULT_DOSStub_bfea {
  strings:
    $key_bfea = { eb 82 [2] 9f 9a [2] d8 98 [2] 9f 89 [2] d1 85 [2] dd 8f [2] ca 84 [2] d1 ca [2] ec }

  condition:
    any of them
}