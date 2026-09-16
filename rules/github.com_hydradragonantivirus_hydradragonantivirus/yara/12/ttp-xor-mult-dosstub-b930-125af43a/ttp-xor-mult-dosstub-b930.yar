rule TTP_XOR_MULT_DOSStub_b930 {
  strings:
    $key_b930 = { ed 58 [2] 99 40 [2] de 42 [2] 99 53 [2] d7 5f [2] db 55 [2] cc 5e [2] d7 10 [2] ea }

  condition:
    any of them
}