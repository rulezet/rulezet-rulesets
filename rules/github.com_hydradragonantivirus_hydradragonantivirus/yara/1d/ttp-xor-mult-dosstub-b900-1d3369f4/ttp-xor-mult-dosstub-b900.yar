rule TTP_XOR_MULT_DOSStub_b900 {
  strings:
    $key_b900 = { ed 68 [2] 99 70 [2] de 72 [2] 99 63 [2] d7 6f [2] db 65 [2] cc 6e [2] d7 20 [2] ea }

  condition:
    any of them
}