rule TTP_XOR_MULT_DOSStub_b95d {
  strings:
    $key_b95d = { ed 35 [2] 99 2d [2] de 2f [2] 99 3e [2] d7 32 [2] db 38 [2] cc 33 [2] d7 7d [2] ea }

  condition:
    any of them
}