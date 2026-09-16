rule TTP_XOR_MULT_DOSStub_bcf6 {
  strings:
    $key_bcf6 = { e8 9e [2] 9c 86 [2] db 84 [2] 9c 95 [2] d2 99 [2] de 93 [2] c9 98 [2] d2 d6 [2] ef }

  condition:
    any of them
}