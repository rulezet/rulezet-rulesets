rule TTP_XOR_MULT_DOSStub_b979 {
  strings:
    $key_b979 = { ed 11 [2] 99 09 [2] de 0b [2] 99 1a [2] d7 16 [2] db 1c [2] cc 17 [2] d7 59 [2] ea }

  condition:
    any of them
}