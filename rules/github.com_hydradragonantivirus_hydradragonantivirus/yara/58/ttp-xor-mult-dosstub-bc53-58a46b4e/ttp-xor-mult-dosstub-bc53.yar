rule TTP_XOR_MULT_DOSStub_bc53 {
  strings:
    $key_bc53 = { e8 3b [2] 9c 23 [2] db 21 [2] 9c 30 [2] d2 3c [2] de 36 [2] c9 3d [2] d2 73 [2] ef }

  condition:
    any of them
}