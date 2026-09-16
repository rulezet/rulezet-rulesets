rule TTP_XOR_MULT_DOSStub_b960 {
  strings:
    $key_b960 = { ed 08 [2] 99 10 [2] de 12 [2] 99 03 [2] d7 0f [2] db 05 [2] cc 0e [2] d7 40 [2] ea }

  condition:
    any of them
}