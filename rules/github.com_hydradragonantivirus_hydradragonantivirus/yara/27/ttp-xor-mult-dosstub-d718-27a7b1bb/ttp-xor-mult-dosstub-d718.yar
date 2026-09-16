rule TTP_XOR_MULT_DOSStub_d718 {
  strings:
    $key_d718 = { 83 70 [2] f7 68 [2] b0 6a [2] f7 7b [2] b9 77 [2] b5 7d [2] a2 76 [2] b9 38 [2] 84 }

  condition:
    any of them
}