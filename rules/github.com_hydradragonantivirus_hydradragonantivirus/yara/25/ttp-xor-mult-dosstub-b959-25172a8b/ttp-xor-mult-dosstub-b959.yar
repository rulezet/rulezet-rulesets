rule TTP_XOR_MULT_DOSStub_b959 {
  strings:
    $key_b959 = { ed 31 [2] 99 29 [2] de 2b [2] 99 3a [2] d7 36 [2] db 3c [2] cc 37 [2] d7 79 [2] ea }

  condition:
    any of them
}