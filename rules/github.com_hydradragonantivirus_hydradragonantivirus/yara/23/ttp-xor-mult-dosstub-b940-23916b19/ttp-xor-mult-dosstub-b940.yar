rule TTP_XOR_MULT_DOSStub_b940 {
  strings:
    $key_b940 = { ed 28 [2] 99 30 [2] de 32 [2] 99 23 [2] d7 2f [2] db 25 [2] cc 2e [2] d7 60 [2] ea }

  condition:
    any of them
}