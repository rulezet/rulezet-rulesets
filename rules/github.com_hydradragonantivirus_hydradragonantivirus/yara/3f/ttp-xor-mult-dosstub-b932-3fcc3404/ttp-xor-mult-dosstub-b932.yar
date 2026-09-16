rule TTP_XOR_MULT_DOSStub_b932 {
  strings:
    $key_b932 = { ed 5a [2] 99 42 [2] de 40 [2] 99 51 [2] d7 5d [2] db 57 [2] cc 5c [2] d7 12 [2] ea }

  condition:
    any of them
}