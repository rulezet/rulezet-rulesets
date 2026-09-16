rule TTP_XOR_MULT_DOSStub_bc15 {
  strings:
    $key_bc15 = { e8 7d [2] 9c 65 [2] db 67 [2] 9c 76 [2] d2 7a [2] de 70 [2] c9 7b [2] d2 35 [2] ef }

  condition:
    any of them
}