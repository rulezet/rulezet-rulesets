rule TTP_XOR_MULT_DOSStub_b93b {
  strings:
    $key_b93b = { ed 53 [2] 99 4b [2] de 49 [2] 99 58 [2] d7 54 [2] db 5e [2] cc 55 [2] d7 1b [2] ea }

  condition:
    any of them
}