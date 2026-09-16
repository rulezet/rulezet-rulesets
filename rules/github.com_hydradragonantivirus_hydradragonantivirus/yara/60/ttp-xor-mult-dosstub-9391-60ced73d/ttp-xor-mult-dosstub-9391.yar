rule TTP_XOR_MULT_DOSStub_9391 {
  strings:
    $key_9391 = { c7 f9 [2] b3 e1 [2] f4 e3 [2] b3 f2 [2] fd fe [2] f1 f4 [2] e6 ff [2] fd b1 [2] c0 }

  condition:
    any of them
}