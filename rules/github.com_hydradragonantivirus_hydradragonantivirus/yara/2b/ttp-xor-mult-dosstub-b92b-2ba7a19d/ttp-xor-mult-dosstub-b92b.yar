rule TTP_XOR_MULT_DOSStub_b92b {
  strings:
    $key_b92b = { ed 43 [2] 99 5b [2] de 59 [2] 99 48 [2] d7 44 [2] db 4e [2] cc 45 [2] d7 0b [2] ea }

  condition:
    any of them
}