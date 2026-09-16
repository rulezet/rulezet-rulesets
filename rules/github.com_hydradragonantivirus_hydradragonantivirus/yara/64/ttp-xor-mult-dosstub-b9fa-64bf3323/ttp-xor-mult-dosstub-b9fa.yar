rule TTP_XOR_MULT_DOSStub_b9fa {
  strings:
    $key_b9fa = { ed 92 [2] 99 8a [2] de 88 [2] 99 99 [2] d7 95 [2] db 9f [2] cc 94 [2] d7 da [2] ea }

  condition:
    any of them
}