rule TTP_XOR_MULT_DOSStub_b95a {
  strings:
    $key_b95a = { ed 32 [2] 99 2a [2] de 28 [2] 99 39 [2] d7 35 [2] db 3f [2] cc 34 [2] d7 7a [2] ea }

  condition:
    any of them
}