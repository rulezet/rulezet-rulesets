rule TTP_XOR_MULT_DOSStub_b911 {
  strings:
    $key_b911 = { ed 79 [2] 99 61 [2] de 63 [2] 99 72 [2] d7 7e [2] db 74 [2] cc 7f [2] d7 31 [2] ea }

  condition:
    any of them
}