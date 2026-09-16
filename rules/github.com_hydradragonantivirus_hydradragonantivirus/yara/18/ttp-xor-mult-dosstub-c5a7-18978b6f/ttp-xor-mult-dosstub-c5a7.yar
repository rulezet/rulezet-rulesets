rule TTP_XOR_MULT_DOSStub_c5a7 {
  strings:
    $key_c5a7 = { 91 cf [2] e5 d7 [2] a2 d5 [2] e5 c4 [2] ab c8 [2] a7 c2 [2] b0 c9 [2] ab 87 [2] 96 }

  condition:
    any of them
}