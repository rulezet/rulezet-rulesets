rule TTP_XOR_MULT_DOSStub_b9fb {
  strings:
    $key_b9fb = { ed 93 [2] 99 8b [2] de 89 [2] 99 98 [2] d7 94 [2] db 9e [2] cc 95 [2] d7 db [2] ea }

  condition:
    any of them
}