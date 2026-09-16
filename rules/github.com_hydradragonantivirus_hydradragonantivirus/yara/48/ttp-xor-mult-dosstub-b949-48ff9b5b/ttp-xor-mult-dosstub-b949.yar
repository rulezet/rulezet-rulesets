rule TTP_XOR_MULT_DOSStub_b949 {
  strings:
    $key_b949 = { ed 21 [2] 99 39 [2] de 3b [2] 99 2a [2] d7 26 [2] db 2c [2] cc 27 [2] d7 69 [2] ea }

  condition:
    any of them
}