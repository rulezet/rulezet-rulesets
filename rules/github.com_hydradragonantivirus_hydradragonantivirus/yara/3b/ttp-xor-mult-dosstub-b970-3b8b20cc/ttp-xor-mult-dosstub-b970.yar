rule TTP_XOR_MULT_DOSStub_b970 {
  strings:
    $key_b970 = { ed 18 [2] 99 00 [2] de 02 [2] 99 13 [2] d7 1f [2] db 15 [2] cc 1e [2] d7 50 [2] ea }

  condition:
    any of them
}