rule TTP_XOR_MULT_DOSStub_b942 {
  strings:
    $key_b942 = { ed 2a [2] 99 32 [2] de 30 [2] 99 21 [2] d7 2d [2] db 27 [2] cc 2c [2] d7 62 [2] ea }

  condition:
    any of them
}