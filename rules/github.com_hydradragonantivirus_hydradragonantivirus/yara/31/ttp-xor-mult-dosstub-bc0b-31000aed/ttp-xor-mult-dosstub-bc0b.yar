rule TTP_XOR_MULT_DOSStub_bc0b {
  strings:
    $key_bc0b = { e8 63 [2] 9c 7b [2] db 79 [2] 9c 68 [2] d2 64 [2] de 6e [2] c9 65 [2] d2 2b [2] ef }

  condition:
    any of them
}