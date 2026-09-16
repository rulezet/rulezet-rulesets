rule TTP_XOR_MULT_DOSStub_bc38 {
  strings:
    $key_bc38 = { e8 50 [2] 9c 48 [2] db 4a [2] 9c 5b [2] d2 57 [2] de 5d [2] c9 56 [2] d2 18 [2] ef }

  condition:
    any of them
}