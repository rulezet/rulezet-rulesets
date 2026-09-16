rule TTP_XOR_MULT_DOSStub_bcf3 {
  strings:
    $key_bcf3 = { e8 9b [2] 9c 83 [2] db 81 [2] 9c 90 [2] d2 9c [2] de 96 [2] c9 9d [2] d2 d3 [2] ef }

  condition:
    any of them
}