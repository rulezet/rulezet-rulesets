rule TTP_XOR_MULT_DOSStub_bce4 {
  strings:
    $key_bce4 = { e8 8c [2] 9c 94 [2] db 96 [2] 9c 87 [2] d2 8b [2] de 81 [2] c9 8a [2] d2 c4 [2] ef }

  condition:
    any of them
}