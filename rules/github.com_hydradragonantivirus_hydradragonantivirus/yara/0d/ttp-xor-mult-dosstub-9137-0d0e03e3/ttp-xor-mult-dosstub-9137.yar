rule TTP_XOR_MULT_DOSStub_9137 {
  strings:
    $key_9137 = { c5 5f [2] b1 47 [2] f6 45 [2] b1 54 [2] ff 58 [2] f3 52 [2] e4 59 [2] ff 17 [2] c2 }

  condition:
    any of them
}