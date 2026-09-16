rule TTP_XOR_MULT_DOSStub_bbd2 {
  strings:
    $key_bbd2 = { ef ba [2] 9b a2 [2] dc a0 [2] 9b b1 [2] d5 bd [2] d9 b7 [2] ce bc [2] d5 f2 [2] e8 }

  condition:
    any of them
}