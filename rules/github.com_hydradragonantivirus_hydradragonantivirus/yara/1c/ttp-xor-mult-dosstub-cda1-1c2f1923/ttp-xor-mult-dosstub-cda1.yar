rule TTP_XOR_MULT_DOSStub_cda1 {
  strings:
    $key_cda1 = { 99 c9 [2] ed d1 [2] aa d3 [2] ed c2 [2] a3 ce [2] af c4 [2] b8 cf [2] a3 81 [2] 9e }

  condition:
    any of them
}