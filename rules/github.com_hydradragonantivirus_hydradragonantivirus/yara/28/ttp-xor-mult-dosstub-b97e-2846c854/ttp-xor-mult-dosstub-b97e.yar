rule TTP_XOR_MULT_DOSStub_b97e {
  strings:
    $key_b97e = { ed 16 [2] 99 0e [2] de 0c [2] 99 1d [2] d7 11 [2] db 1b [2] cc 10 [2] d7 5e [2] ea }

  condition:
    any of them
}