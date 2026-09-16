rule TTP_XOR_MULT_DOSStub_b93d {
  strings:
    $key_b93d = { ed 55 [2] 99 4d [2] de 4f [2] 99 5e [2] d7 52 [2] db 58 [2] cc 53 [2] d7 1d [2] ea }

  condition:
    any of them
}