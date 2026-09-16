rule TTP_XOR_MULT_DOSStub_b93c {
  strings:
    $key_b93c = { ed 54 [2] 99 4c [2] de 4e [2] 99 5f [2] d7 53 [2] db 59 [2] cc 52 [2] d7 1c [2] ea }

  condition:
    any of them
}