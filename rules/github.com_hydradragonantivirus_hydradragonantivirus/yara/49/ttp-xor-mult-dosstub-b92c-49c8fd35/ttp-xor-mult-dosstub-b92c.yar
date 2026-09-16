rule TTP_XOR_MULT_DOSStub_b92c {
  strings:
    $key_b92c = { ed 44 [2] 99 5c [2] de 5e [2] 99 4f [2] d7 43 [2] db 49 [2] cc 42 [2] d7 0c [2] ea }

  condition:
    any of them
}