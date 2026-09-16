rule TTP_XOR_MULT_DOSStub_b937 {
  strings:
    $key_b937 = { ed 5f [2] 99 47 [2] de 45 [2] 99 54 [2] d7 58 [2] db 52 [2] cc 59 [2] d7 17 [2] ea }

  condition:
    any of them
}