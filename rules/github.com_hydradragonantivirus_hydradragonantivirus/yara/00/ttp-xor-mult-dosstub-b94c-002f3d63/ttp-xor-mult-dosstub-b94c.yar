rule TTP_XOR_MULT_DOSStub_b94c {
  strings:
    $key_b94c = { ed 24 [2] 99 3c [2] de 3e [2] 99 2f [2] d7 23 [2] db 29 [2] cc 22 [2] d7 6c [2] ea }

  condition:
    any of them
}