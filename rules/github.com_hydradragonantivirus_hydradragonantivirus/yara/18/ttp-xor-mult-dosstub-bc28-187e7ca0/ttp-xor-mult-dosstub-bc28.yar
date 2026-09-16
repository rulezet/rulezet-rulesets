rule TTP_XOR_MULT_DOSStub_bc28 {
  strings:
    $key_bc28 = { e8 40 [2] 9c 58 [2] db 5a [2] 9c 4b [2] d2 47 [2] de 4d [2] c9 46 [2] d2 08 [2] ef }

  condition:
    any of them
}