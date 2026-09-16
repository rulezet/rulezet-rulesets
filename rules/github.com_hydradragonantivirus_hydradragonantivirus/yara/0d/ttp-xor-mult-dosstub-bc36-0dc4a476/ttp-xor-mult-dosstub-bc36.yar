rule TTP_XOR_MULT_DOSStub_bc36 {
  strings:
    $key_bc36 = { e8 5e [2] 9c 46 [2] db 44 [2] 9c 55 [2] d2 59 [2] de 53 [2] c9 58 [2] d2 16 [2] ef }

  condition:
    any of them
}