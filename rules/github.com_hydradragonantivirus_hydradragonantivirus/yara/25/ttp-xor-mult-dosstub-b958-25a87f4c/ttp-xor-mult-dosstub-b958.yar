rule TTP_XOR_MULT_DOSStub_b958 {
  strings:
    $key_b958 = { ed 30 [2] 99 28 [2] de 2a [2] 99 3b [2] d7 37 [2] db 3d [2] cc 36 [2] d7 78 [2] ea }

  condition:
    any of them
}