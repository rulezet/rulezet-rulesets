rule TTP_XOR_MULT_DOSStub_9590 {
  strings:
    $key_9590 = { c1 f8 [2] b5 e0 [2] f2 e2 [2] b5 f3 [2] fb ff [2] f7 f5 [2] e0 fe [2] fb b0 [2] c6 }

  condition:
    any of them
}