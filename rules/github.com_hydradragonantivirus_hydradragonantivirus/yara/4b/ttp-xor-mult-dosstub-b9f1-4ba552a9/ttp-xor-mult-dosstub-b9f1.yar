rule TTP_XOR_MULT_DOSStub_b9f1 {
  strings:
    $key_b9f1 = { ed 99 [2] 99 81 [2] de 83 [2] 99 92 [2] d7 9e [2] db 94 [2] cc 9f [2] d7 d1 [2] ea }

  condition:
    any of them
}