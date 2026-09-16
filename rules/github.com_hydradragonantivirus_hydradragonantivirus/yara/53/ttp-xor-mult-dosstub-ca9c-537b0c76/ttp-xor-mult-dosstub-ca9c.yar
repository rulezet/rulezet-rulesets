rule TTP_XOR_MULT_DOSStub_ca9c {
  strings:
    $key_ca9c = { 9e f4 [2] ea ec [2] ad ee [2] ea ff [2] a4 f3 [2] a8 f9 [2] bf f2 [2] a4 bc [2] 99 }

  condition:
    any of them
}