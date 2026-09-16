rule TTP_XOR_MULT_DOSStub_b968 {
  strings:
    $key_b968 = { ed 00 [2] 99 18 [2] de 1a [2] 99 0b [2] d7 07 [2] db 0d [2] cc 06 [2] d7 48 [2] ea }

  condition:
    any of them
}