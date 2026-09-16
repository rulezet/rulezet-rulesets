rule TTP_XOR_MULT_DOSStub_b964 {
  strings:
    $key_b964 = { ed 0c [2] 99 14 [2] de 16 [2] 99 07 [2] d7 0b [2] db 01 [2] cc 0a [2] d7 44 [2] ea }

  condition:
    any of them
}