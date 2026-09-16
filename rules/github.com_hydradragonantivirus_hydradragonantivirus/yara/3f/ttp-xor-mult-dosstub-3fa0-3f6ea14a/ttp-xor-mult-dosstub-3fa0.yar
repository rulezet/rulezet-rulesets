rule TTP_XOR_MULT_DOSStub_3fa0 {
  strings:
    $key_3fa0 = { 6b c8 [2] 1f d0 [2] 58 d2 [2] 1f c3 [2] 51 cf [2] 5d c5 [2] 4a ce [2] 51 80 [2] 6c }

  condition:
    any of them
}