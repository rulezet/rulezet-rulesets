rule TTP_XOR_MULT_DOSStub_b977 {
  strings:
    $key_b977 = { ed 1f [2] 99 07 [2] de 05 [2] 99 14 [2] d7 18 [2] db 12 [2] cc 19 [2] d7 57 [2] ea }

  condition:
    any of them
}