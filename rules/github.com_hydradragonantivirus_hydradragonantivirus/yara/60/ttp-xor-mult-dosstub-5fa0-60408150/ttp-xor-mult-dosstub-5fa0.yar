rule TTP_XOR_MULT_DOSStub_5fa0 {
  strings:
    $key_5fa0 = { 0b c8 [2] 7f d0 [2] 38 d2 [2] 7f c3 [2] 31 cf [2] 3d c5 [2] 2a ce [2] 31 80 [2] 0c }

  condition:
    any of them
}