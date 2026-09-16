rule TTP_XOR_MULT_DOSStub_d732 {
  strings:
    $key_d732 = { 83 5a [2] f7 42 [2] b0 40 [2] f7 51 [2] b9 5d [2] b5 57 [2] a2 5c [2] b9 12 [2] 84 }

  condition:
    any of them
}