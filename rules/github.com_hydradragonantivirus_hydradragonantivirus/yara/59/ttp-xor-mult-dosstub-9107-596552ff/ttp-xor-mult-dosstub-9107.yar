rule TTP_XOR_MULT_DOSStub_9107 {
  strings:
    $key_9107 = { c5 6f [2] b1 77 [2] f6 75 [2] b1 64 [2] ff 68 [2] f3 62 [2] e4 69 [2] ff 27 [2] c2 }

  condition:
    any of them
}