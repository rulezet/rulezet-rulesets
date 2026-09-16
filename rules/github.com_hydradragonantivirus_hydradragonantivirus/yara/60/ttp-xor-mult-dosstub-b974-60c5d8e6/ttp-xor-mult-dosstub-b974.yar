rule TTP_XOR_MULT_DOSStub_b974 {
  strings:
    $key_b974 = { ed 1c [2] 99 04 [2] de 06 [2] 99 17 [2] d7 1b [2] db 11 [2] cc 1a [2] d7 54 [2] ea }

  condition:
    any of them
}