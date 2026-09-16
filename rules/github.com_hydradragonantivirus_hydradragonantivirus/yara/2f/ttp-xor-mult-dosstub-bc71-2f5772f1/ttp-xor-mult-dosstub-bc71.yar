rule TTP_XOR_MULT_DOSStub_bc71 {
  strings:
    $key_bc71 = { e8 19 [2] 9c 01 [2] db 03 [2] 9c 12 [2] d2 1e [2] de 14 [2] c9 1f [2] d2 51 [2] ef }

  condition:
    any of them
}