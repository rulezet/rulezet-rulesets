rule TTP_XOR_MULT_DOSStub_bc75 {
  strings:
    $key_bc75 = { e8 1d [2] 9c 05 [2] db 07 [2] 9c 16 [2] d2 1a [2] de 10 [2] c9 1b [2] d2 55 [2] ef }

  condition:
    any of them
}