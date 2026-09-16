rule TTP_XOR_MULT_DOSStub_b934 {
  strings:
    $key_b934 = { ed 5c [2] 99 44 [2] de 46 [2] 99 57 [2] d7 5b [2] db 51 [2] cc 5a [2] d7 14 [2] ea }

  condition:
    any of them
}