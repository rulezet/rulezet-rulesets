rule TTP_XOR_MULT_DOSStub_bc07 {
  strings:
    $key_bc07 = { e8 6f [2] 9c 77 [2] db 75 [2] 9c 64 [2] d2 68 [2] de 62 [2] c9 69 [2] d2 27 [2] ef }

  condition:
    any of them
}