rule TTP_XOR_MULT_DOSStub_b95f {
  strings:
    $key_b95f = { ed 37 [2] 99 2f [2] de 2d [2] 99 3c [2] d7 30 [2] db 3a [2] cc 31 [2] d7 7f [2] ea }

  condition:
    any of them
}