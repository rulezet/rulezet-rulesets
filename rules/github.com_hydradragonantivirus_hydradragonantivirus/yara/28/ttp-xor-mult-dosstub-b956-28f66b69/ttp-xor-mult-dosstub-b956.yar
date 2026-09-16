rule TTP_XOR_MULT_DOSStub_b956 {
  strings:
    $key_b956 = { ed 3e [2] 99 26 [2] de 24 [2] 99 35 [2] d7 39 [2] db 33 [2] cc 38 [2] d7 76 [2] ea }

  condition:
    any of them
}