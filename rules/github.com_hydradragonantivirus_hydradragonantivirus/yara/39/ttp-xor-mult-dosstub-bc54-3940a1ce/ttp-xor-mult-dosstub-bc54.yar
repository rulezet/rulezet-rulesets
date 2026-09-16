rule TTP_XOR_MULT_DOSStub_bc54 {
  strings:
    $key_bc54 = { e8 3c [2] 9c 24 [2] db 26 [2] 9c 37 [2] d2 3b [2] de 31 [2] c9 3a [2] d2 74 [2] ef }

  condition:
    any of them
}