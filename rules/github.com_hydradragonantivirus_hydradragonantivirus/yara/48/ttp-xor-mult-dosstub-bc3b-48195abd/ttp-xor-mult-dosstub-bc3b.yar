rule TTP_XOR_MULT_DOSStub_bc3b {
  strings:
    $key_bc3b = { e8 53 [2] 9c 4b [2] db 49 [2] 9c 58 [2] d2 54 [2] de 5e [2] c9 55 [2] d2 1b [2] ef }

  condition:
    any of them
}