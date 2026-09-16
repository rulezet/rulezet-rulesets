rule TTP_XOR_MULT_DOSStub_bc39 {
  strings:
    $key_bc39 = { e8 51 [2] 9c 49 [2] db 4b [2] 9c 5a [2] d2 56 [2] de 5c [2] c9 57 [2] d2 19 [2] ef }

  condition:
    any of them
}