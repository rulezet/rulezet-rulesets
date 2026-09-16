rule TTP_XOR_MULT_DOSStub_bc5b {
  strings:
    $key_bc5b = { e8 33 [2] 9c 2b [2] db 29 [2] 9c 38 [2] d2 34 [2] de 3e [2] c9 35 [2] d2 7b [2] ef }

  condition:
    any of them
}