rule TTP_XOR_MULT_DOSStub_d632 {
  strings:
    $key_d632 = { 82 5a [2] f6 42 [2] b1 40 [2] f6 51 [2] b8 5d [2] b4 57 [2] a3 5c [2] b8 12 [2] 85 }

  condition:
    any of them
}