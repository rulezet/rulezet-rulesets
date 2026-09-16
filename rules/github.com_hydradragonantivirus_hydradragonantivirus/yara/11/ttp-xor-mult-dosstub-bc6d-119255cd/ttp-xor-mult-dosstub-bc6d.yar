rule TTP_XOR_MULT_DOSStub_bc6d {
  strings:
    $key_bc6d = { e8 05 [2] 9c 1d [2] db 1f [2] 9c 0e [2] d2 02 [2] de 08 [2] c9 03 [2] d2 4d [2] ef }

  condition:
    any of them
}