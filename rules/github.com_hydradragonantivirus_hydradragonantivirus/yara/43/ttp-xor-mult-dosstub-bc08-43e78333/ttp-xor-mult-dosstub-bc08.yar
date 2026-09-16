rule TTP_XOR_MULT_DOSStub_bc08 {
  strings:
    $key_bc08 = { e8 60 [2] 9c 78 [2] db 7a [2] 9c 6b [2] d2 67 [2] de 6d [2] c9 66 [2] d2 28 [2] ef }

  condition:
    any of them
}