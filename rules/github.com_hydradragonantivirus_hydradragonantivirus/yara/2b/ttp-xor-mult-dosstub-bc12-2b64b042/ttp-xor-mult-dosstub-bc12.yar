rule TTP_XOR_MULT_DOSStub_bc12 {
  strings:
    $key_bc12 = { e8 7a [2] 9c 62 [2] db 60 [2] 9c 71 [2] d2 7d [2] de 77 [2] c9 7c [2] d2 32 [2] ef }

  condition:
    any of them
}