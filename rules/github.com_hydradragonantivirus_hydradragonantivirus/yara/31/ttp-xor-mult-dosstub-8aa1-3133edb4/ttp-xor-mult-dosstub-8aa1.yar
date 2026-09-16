rule TTP_XOR_MULT_DOSStub_8aa1 {
  strings:
    $key_8aa1 = { de c9 [2] aa d1 [2] ed d3 [2] aa c2 [2] e4 ce [2] e8 c4 [2] ff cf [2] e4 81 [2] d9 }

  condition:
    any of them
}