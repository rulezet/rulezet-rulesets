rule TTP_XOR_MULT_DOSStub_bcf0 {
  strings:
    $key_bcf0 = { e8 98 [2] 9c 80 [2] db 82 [2] 9c 93 [2] d2 9f [2] de 95 [2] c9 9e [2] d2 d0 [2] ef }

  condition:
    any of them
}