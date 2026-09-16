rule TTP_XOR_MULT_DOSStub_a419 {
  strings:
    $key_a419 = { f0 71 [2] 84 69 [2] c3 6b [2] 84 7a [2] ca 76 [2] c6 7c [2] d1 77 [2] ca 39 [2] f7 }

  condition:
    any of them
}