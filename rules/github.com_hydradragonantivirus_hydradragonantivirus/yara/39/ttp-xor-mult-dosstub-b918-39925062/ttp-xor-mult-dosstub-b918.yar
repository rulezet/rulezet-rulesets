rule TTP_XOR_MULT_DOSStub_b918 {
  strings:
    $key_b918 = { ed 70 [2] 99 68 [2] de 6a [2] 99 7b [2] d7 77 [2] db 7d [2] cc 76 [2] d7 38 [2] ea }

  condition:
    any of them
}