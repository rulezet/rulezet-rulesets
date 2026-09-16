rule TTP_XOR_MULT_DOSStub_9116 {
  strings:
    $key_9116 = { c5 7e [2] b1 66 [2] f6 64 [2] b1 75 [2] ff 79 [2] f3 73 [2] e4 78 [2] ff 36 [2] c2 }

  condition:
    any of them
}