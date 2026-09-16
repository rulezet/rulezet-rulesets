rule TTP_XOR_MULT_DOSStub_bc67 {
  strings:
    $key_bc67 = { e8 0f [2] 9c 17 [2] db 15 [2] 9c 04 [2] d2 08 [2] de 02 [2] c9 09 [2] d2 47 [2] ef }

  condition:
    any of them
}