rule TTP_XOR_MULT_DOSStub_b97c {
  strings:
    $key_b97c = { ed 14 [2] 99 0c [2] de 0e [2] 99 1f [2] d7 13 [2] db 19 [2] cc 12 [2] d7 5c [2] ea }

  condition:
    any of them
}