rule TTP_XOR_MULT_DOSStub_9157 {
  strings:
    $key_9157 = { c5 3f [2] b1 27 [2] f6 25 [2] b1 34 [2] ff 38 [2] f3 32 [2] e4 39 [2] ff 77 [2] c2 }

  condition:
    any of them
}