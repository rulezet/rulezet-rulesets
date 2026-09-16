rule TTP_XOR_MULT_DOSStub_c5a0 {
  strings:
    $key_c5a0 = { 91 c8 [2] e5 d0 [2] a2 d2 [2] e5 c3 [2] ab cf [2] a7 c5 [2] b0 ce [2] ab 80 [2] 96 }

  condition:
    any of them
}