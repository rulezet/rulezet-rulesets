rule TTP_XOR_MULT_DOSStub_da9c {
  strings:
    $key_da9c = { 8e f4 [2] fa ec [2] bd ee [2] fa ff [2] b4 f3 [2] b8 f9 [2] af f2 [2] b4 bc [2] 89 }

  condition:
    any of them
}