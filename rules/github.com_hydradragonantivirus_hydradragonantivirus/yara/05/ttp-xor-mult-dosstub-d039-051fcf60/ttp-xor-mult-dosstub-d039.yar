rule TTP_XOR_MULT_DOSStub_d039 {
  strings:
    $key_d039 = { 84 51 [2] f0 49 [2] b7 4b [2] f0 5a [2] be 56 [2] b2 5c [2] a5 57 [2] be 19 [2] 83 }

  condition:
    any of them
}