rule TTP_XOR_MULT_DOSStub_9171 {
  strings:
    $key_9171 = { c5 19 [2] b1 01 [2] f6 03 [2] b1 12 [2] ff 1e [2] f3 14 [2] e4 1f [2] ff 51 [2] c2 }

  condition:
    any of them
}