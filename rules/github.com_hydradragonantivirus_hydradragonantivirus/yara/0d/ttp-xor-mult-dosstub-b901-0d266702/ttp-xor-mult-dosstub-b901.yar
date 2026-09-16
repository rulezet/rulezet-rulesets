rule TTP_XOR_MULT_DOSStub_b901 {
  strings:
    $key_b901 = { ed 69 [2] 99 71 [2] de 73 [2] 99 62 [2] d7 6e [2] db 64 [2] cc 6f [2] d7 21 [2] ea }

  condition:
    any of them
}