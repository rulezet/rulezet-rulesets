rule TTP_XOR_MULT_DOSStub_b9e0 {
  strings:
    $key_b9e0 = { ed 88 [2] 99 90 [2] de 92 [2] 99 83 [2] d7 8f [2] db 85 [2] cc 8e [2] d7 c0 [2] ea }

  condition:
    any of them
}