rule TTP_XOR_MULT_DOSStub_8337 {
  strings:
    $key_8337 = { d7 5f [2] a3 47 [2] e4 45 [2] a3 54 [2] ed 58 [2] e1 52 [2] f6 59 [2] ed 17 [2] d0 }

  condition:
    any of them
}