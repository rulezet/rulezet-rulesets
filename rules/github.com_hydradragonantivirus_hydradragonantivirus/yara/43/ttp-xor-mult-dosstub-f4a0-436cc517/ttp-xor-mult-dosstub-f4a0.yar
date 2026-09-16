rule TTP_XOR_MULT_DOSStub_f4a0 {
  strings:
    $key_f4a0 = { a0 c8 [2] d4 d0 [2] 93 d2 [2] d4 c3 [2] 9a cf [2] 96 c5 [2] 81 ce [2] 9a 80 [2] a7 }

  condition:
    any of them
}