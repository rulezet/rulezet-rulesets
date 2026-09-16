rule TTP_XOR_MULT_DOSStub_bcb8 {
  strings:
    $key_bcb8 = { e8 d0 [2] 9c c8 [2] db ca [2] 9c db [2] d2 d7 [2] de dd [2] c9 d6 [2] d2 98 [2] ef }

  condition:
    any of them
}