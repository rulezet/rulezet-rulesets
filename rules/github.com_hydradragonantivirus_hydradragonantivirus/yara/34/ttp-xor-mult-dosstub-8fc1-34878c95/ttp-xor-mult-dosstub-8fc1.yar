rule TTP_XOR_MULT_DOSStub_8fc1 {
  strings:
    $key_8fc1 = { db a9 [2] af b1 [2] e8 b3 [2] af a2 [2] e1 ae [2] ed a4 [2] fa af [2] e1 e1 [2] dc }

  condition:
    any of them
}