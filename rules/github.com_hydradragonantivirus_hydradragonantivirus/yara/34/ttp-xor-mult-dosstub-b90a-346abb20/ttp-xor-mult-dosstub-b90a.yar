rule TTP_XOR_MULT_DOSStub_b90a {
  strings:
    $key_b90a = { ed 62 [2] 99 7a [2] de 78 [2] 99 69 [2] d7 65 [2] db 6f [2] cc 64 [2] d7 2a [2] ea }

  condition:
    any of them
}