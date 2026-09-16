rule TTP_XOR_MULT_DOSStub_b9fc {
  strings:
    $key_b9fc = { ed 94 [2] 99 8c [2] de 8e [2] 99 9f [2] d7 93 [2] db 99 [2] cc 92 [2] d7 dc [2] ea }

  condition:
    any of them
}