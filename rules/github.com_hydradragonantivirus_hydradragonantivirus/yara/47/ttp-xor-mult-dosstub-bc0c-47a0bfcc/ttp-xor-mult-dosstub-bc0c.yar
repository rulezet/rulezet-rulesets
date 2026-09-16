rule TTP_XOR_MULT_DOSStub_bc0c {
  strings:
    $key_bc0c = { e8 64 [2] 9c 7c [2] db 7e [2] 9c 6f [2] d2 63 [2] de 69 [2] c9 62 [2] d2 2c [2] ef }

  condition:
    any of them
}