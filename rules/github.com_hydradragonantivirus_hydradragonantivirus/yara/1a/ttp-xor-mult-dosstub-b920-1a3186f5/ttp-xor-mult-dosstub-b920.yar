rule TTP_XOR_MULT_DOSStub_b920 {
  strings:
    $key_b920 = { ed 48 [2] 99 50 [2] de 52 [2] 99 43 [2] d7 4f [2] db 45 [2] cc 4e [2] d7 00 [2] ea }

  condition:
    any of them
}