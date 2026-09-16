rule TTP_XOR_MULT_DOSStub_b91f {
  strings:
    $key_b91f = { ed 77 [2] 99 6f [2] de 6d [2] 99 7c [2] d7 70 [2] db 7a [2] cc 71 [2] d7 3f [2] ea }

  condition:
    any of them
}