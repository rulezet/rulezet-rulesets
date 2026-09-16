rule TTP_XOR_MULT_DOSStub_bc66 {
  strings:
    $key_bc66 = { e8 0e [2] 9c 16 [2] db 14 [2] 9c 05 [2] d2 09 [2] de 03 [2] c9 08 [2] d2 46 [2] ef }

  condition:
    any of them
}