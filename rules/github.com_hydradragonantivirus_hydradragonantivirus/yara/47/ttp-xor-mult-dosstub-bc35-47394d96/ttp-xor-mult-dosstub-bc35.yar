rule TTP_XOR_MULT_DOSStub_bc35 {
  strings:
    $key_bc35 = { e8 5d [2] 9c 45 [2] db 47 [2] 9c 56 [2] d2 5a [2] de 50 [2] c9 5b [2] d2 15 [2] ef }

  condition:
    any of them
}