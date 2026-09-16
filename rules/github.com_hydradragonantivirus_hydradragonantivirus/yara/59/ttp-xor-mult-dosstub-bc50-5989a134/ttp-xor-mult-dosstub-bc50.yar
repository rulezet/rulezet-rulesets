rule TTP_XOR_MULT_DOSStub_bc50 {
  strings:
    $key_bc50 = { e8 38 [2] 9c 20 [2] db 22 [2] 9c 33 [2] d2 3f [2] de 35 [2] c9 3e [2] d2 70 [2] ef }

  condition:
    any of them
}