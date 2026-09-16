rule TTP_XOR_MULT_DOSStub_b9e3 {
  strings:
    $key_b9e3 = { ed 8b [2] 99 93 [2] de 91 [2] 99 80 [2] d7 8c [2] db 86 [2] cc 8d [2] d7 c3 [2] ea }

  condition:
    any of them
}