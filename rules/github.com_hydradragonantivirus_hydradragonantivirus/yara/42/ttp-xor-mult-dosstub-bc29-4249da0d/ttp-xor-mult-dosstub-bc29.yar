rule TTP_XOR_MULT_DOSStub_bc29 {
  strings:
    $key_bc29 = { e8 41 [2] 9c 59 [2] db 5b [2] 9c 4a [2] d2 46 [2] de 4c [2] c9 47 [2] d2 09 [2] ef }

  condition:
    any of them
}