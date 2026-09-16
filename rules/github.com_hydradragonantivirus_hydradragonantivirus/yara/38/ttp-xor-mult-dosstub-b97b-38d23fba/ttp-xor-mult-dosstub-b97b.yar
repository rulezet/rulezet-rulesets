rule TTP_XOR_MULT_DOSStub_b97b {
  strings:
    $key_b97b = { ed 13 [2] 99 0b [2] de 09 [2] 99 18 [2] d7 14 [2] db 1e [2] cc 15 [2] d7 5b [2] ea }

  condition:
    any of them
}