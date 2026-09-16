rule TTP_XOR_MULT_DOSStub_b954 {
  strings:
    $key_b954 = { ed 3c [2] 99 24 [2] de 26 [2] 99 37 [2] d7 3b [2] db 31 [2] cc 3a [2] d7 74 [2] ea }

  condition:
    any of them
}