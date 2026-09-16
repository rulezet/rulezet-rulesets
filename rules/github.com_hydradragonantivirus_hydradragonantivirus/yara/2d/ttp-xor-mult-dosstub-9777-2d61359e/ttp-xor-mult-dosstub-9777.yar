rule TTP_XOR_MULT_DOSStub_9777 {
  strings:
    $key_9777 = { c3 1f [2] b7 07 [2] f0 05 [2] b7 14 [2] f9 18 [2] f5 12 [2] e2 19 [2] f9 57 [2] c4 }

  condition:
    any of them
}