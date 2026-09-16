rule TTP_XOR_MULT_DOSStub_b9e9 {
  strings:
    $key_b9e9 = { ed 81 [2] 99 99 [2] de 9b [2] 99 8a [2] d7 86 [2] db 8c [2] cc 87 [2] d7 c9 [2] ea }

  condition:
    any of them
}