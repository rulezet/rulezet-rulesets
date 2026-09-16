rule TTP_XOR_MULT_DOSStub_d7f4 {
  strings:
    $key_d7f4 = { 83 9c [2] f7 84 [2] b0 86 [2] f7 97 [2] b9 9b [2] b5 91 [2] a2 9a [2] b9 d4 [2] 84 }

  condition:
    any of them
}