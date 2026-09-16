rule TTP_XOR_MULT_DOSStub_9791 {
  strings:
    $key_9791 = { c3 f9 [2] b7 e1 [2] f0 e3 [2] b7 f2 [2] f9 fe [2] f5 f4 [2] e2 ff [2] f9 b1 [2] c4 }

  condition:
    any of them
}