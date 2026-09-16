rule TTP_XOR_MULT_DOSStub_bce9 {
  strings:
    $key_bce9 = { e8 81 [2] 9c 99 [2] db 9b [2] 9c 8a [2] d2 86 [2] de 8c [2] c9 87 [2] d2 c9 [2] ef }

  condition:
    any of them
}