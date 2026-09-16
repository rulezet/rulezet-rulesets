rule TTP_XOR_MULT_DOSStub_d034 {
  strings:
    $key_d034 = { 84 5c [2] f0 44 [2] b7 46 [2] f0 57 [2] be 5b [2] b2 51 [2] a5 5a [2] be 14 [2] 83 }

  condition:
    any of them
}