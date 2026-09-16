rule TTP_XOR_MULT_DOSStub_24a7 {
  strings:
    $key_24a7 = { 70 cf [2] 04 d7 [2] 43 d5 [2] 04 c4 [2] 4a c8 [2] 46 c2 [2] 51 c9 [2] 4a 87 [2] 77 }

  condition:
    any of them
}