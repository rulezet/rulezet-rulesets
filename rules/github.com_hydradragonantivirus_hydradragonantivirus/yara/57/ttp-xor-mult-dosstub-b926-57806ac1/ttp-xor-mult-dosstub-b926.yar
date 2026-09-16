rule TTP_XOR_MULT_DOSStub_b926 {
  strings:
    $key_b926 = { ed 4e [2] 99 56 [2] de 54 [2] 99 45 [2] d7 49 [2] db 43 [2] cc 48 [2] d7 06 [2] ea }

  condition:
    any of them
}