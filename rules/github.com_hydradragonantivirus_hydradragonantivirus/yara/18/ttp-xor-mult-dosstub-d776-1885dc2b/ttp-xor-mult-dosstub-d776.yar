rule TTP_XOR_MULT_DOSStub_d776 {
  strings:
    $key_d776 = { 83 1e [2] f7 06 [2] b0 04 [2] f7 15 [2] b9 19 [2] b5 13 [2] a2 18 [2] b9 56 [2] 84 }

  condition:
    any of them
}