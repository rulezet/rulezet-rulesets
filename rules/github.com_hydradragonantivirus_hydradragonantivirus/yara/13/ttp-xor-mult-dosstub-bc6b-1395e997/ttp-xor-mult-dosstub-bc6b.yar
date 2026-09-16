rule TTP_XOR_MULT_DOSStub_bc6b {
  strings:
    $key_bc6b = { e8 03 [2] 9c 1b [2] db 19 [2] 9c 08 [2] d2 04 [2] de 0e [2] c9 05 [2] d2 4b [2] ef }

  condition:
    any of them
}