rule TTP_XOR_MULT_DOSStub_b9f5 {
  strings:
    $key_b9f5 = { ed 9d [2] 99 85 [2] de 87 [2] 99 96 [2] d7 9a [2] db 90 [2] cc 9b [2] d7 d5 [2] ea }

  condition:
    any of them
}