rule TTP_XOR_MULT_DOSStub_b95c {
  strings:
    $key_b95c = { ed 34 [2] 99 2c [2] de 2e [2] 99 3f [2] d7 33 [2] db 39 [2] cc 32 [2] d7 7c [2] ea }

  condition:
    any of them
}