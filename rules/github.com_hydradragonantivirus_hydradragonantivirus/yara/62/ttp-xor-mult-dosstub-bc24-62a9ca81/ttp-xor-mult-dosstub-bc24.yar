rule TTP_XOR_MULT_DOSStub_bc24 {
  strings:
    $key_bc24 = { e8 4c [2] 9c 54 [2] db 56 [2] 9c 47 [2] d2 4b [2] de 41 [2] c9 4a [2] d2 04 [2] ef }

  condition:
    any of them
}