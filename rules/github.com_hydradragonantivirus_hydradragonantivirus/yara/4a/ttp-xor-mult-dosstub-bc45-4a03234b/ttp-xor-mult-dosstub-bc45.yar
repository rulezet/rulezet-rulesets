rule TTP_XOR_MULT_DOSStub_bc45 {
  strings:
    $key_bc45 = { e8 2d [2] 9c 35 [2] db 37 [2] 9c 26 [2] d2 2a [2] de 20 [2] c9 2b [2] d2 65 [2] ef }

  condition:
    any of them
}