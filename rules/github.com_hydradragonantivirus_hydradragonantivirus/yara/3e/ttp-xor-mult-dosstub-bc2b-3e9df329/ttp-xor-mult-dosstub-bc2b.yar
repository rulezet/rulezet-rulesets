rule TTP_XOR_MULT_DOSStub_bc2b {
  strings:
    $key_bc2b = { e8 43 [2] 9c 5b [2] db 59 [2] 9c 48 [2] d2 44 [2] de 4e [2] c9 45 [2] d2 0b [2] ef }

  condition:
    any of them
}