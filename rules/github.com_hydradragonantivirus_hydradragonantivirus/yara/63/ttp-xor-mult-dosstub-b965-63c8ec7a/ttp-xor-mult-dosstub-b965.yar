rule TTP_XOR_MULT_DOSStub_b965 {
  strings:
    $key_b965 = { ed 0d [2] 99 15 [2] de 17 [2] 99 06 [2] d7 0a [2] db 00 [2] cc 0b [2] d7 45 [2] ea }

  condition:
    any of them
}