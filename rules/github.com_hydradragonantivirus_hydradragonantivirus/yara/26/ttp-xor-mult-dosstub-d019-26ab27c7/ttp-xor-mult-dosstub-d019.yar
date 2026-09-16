rule TTP_XOR_MULT_DOSStub_d019 {
  strings:
    $key_d019 = { 84 71 [2] f0 69 [2] b7 6b [2] f0 7a [2] be 76 [2] b2 7c [2] a5 77 [2] be 39 [2] 83 }

  condition:
    any of them
}