rule TTP_XOR_MULT_DOSStub_bcfa {
  strings:
    $key_bcfa = { e8 92 [2] 9c 8a [2] db 88 [2] 9c 99 [2] d2 95 [2] de 9f [2] c9 94 [2] d2 da [2] ef }

  condition:
    any of them
}