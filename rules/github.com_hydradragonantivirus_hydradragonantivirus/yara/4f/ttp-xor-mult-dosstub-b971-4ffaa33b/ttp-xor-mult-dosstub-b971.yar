rule TTP_XOR_MULT_DOSStub_b971 {
  strings:
    $key_b971 = { ed 19 [2] 99 01 [2] de 03 [2] 99 12 [2] d7 1e [2] db 14 [2] cc 1f [2] d7 51 [2] ea }

  condition:
    any of them
}