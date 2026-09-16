rule TTP_XOR_MULT_DOSStub_d339 {
  strings:
    $key_d339 = { 87 51 [2] f3 49 [2] b4 4b [2] f3 5a [2] bd 56 [2] b1 5c [2] a6 57 [2] bd 19 [2] 80 }

  condition:
    any of them
}