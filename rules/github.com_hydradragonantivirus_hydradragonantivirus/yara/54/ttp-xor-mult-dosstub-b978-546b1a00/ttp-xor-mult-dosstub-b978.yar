rule TTP_XOR_MULT_DOSStub_b978 {
  strings:
    $key_b978 = { ed 10 [2] 99 08 [2] de 0a [2] 99 1b [2] d7 17 [2] db 1d [2] cc 16 [2] d7 58 [2] ea }

  condition:
    any of them
}