rule TTP_XOR_MULT_DOSStub_b917 {
  strings:
    $key_b917 = { ed 7f [2] 99 67 [2] de 65 [2] 99 74 [2] d7 78 [2] db 72 [2] cc 79 [2] d7 37 [2] ea }

  condition:
    any of them
}