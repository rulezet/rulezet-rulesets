rule TTP_XOR_MULT_DOSStub_b9f7 {
  strings:
    $key_b9f7 = { ed 9f [2] 99 87 [2] de 85 [2] 99 94 [2] d7 98 [2] db 92 [2] cc 99 [2] d7 d7 [2] ea }

  condition:
    any of them
}