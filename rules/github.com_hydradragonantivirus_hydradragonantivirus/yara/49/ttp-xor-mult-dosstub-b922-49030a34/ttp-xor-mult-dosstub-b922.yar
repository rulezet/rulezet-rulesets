rule TTP_XOR_MULT_DOSStub_b922 {
  strings:
    $key_b922 = { ed 4a [2] 99 52 [2] de 50 [2] 99 41 [2] d7 4d [2] db 47 [2] cc 4c [2] d7 02 [2] ea }

  condition:
    any of them
}