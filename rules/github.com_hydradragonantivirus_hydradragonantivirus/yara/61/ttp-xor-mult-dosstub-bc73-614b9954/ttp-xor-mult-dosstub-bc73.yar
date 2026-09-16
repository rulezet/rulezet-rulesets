rule TTP_XOR_MULT_DOSStub_bc73 {
  strings:
    $key_bc73 = { e8 1b [2] 9c 03 [2] db 01 [2] 9c 10 [2] d2 1c [2] de 16 [2] c9 1d [2] d2 53 [2] ef }

  condition:
    any of them
}