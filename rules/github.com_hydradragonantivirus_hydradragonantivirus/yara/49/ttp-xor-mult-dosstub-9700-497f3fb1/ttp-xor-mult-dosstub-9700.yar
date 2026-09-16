rule TTP_XOR_MULT_DOSStub_9700 {
  strings:
    $key_9700 = { c3 68 [2] b7 70 [2] f0 72 [2] b7 63 [2] f9 6f [2] f5 65 [2] e2 6e [2] f9 20 [2] c4 }

  condition:
    any of them
}