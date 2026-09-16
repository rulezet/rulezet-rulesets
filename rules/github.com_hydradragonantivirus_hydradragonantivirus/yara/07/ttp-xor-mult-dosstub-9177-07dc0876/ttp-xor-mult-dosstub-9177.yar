rule TTP_XOR_MULT_DOSStub_9177 {
  strings:
    $key_9177 = { c5 1f [2] b1 07 [2] f6 05 [2] b1 14 [2] ff 18 [2] f3 12 [2] e4 19 [2] ff 57 [2] c2 }

  condition:
    any of them
}