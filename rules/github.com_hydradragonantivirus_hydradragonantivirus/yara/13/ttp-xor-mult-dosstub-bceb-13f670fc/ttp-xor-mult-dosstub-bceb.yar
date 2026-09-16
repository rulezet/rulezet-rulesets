rule TTP_XOR_MULT_DOSStub_bceb {
  strings:
    $key_bceb = { e8 83 [2] 9c 9b [2] db 99 [2] 9c 88 [2] d2 84 [2] de 8e [2] c9 85 [2] d2 cb [2] ef }

  condition:
    any of them
}