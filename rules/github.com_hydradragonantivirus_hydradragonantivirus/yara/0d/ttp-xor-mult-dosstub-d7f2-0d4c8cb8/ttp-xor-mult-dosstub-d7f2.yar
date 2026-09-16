rule TTP_XOR_MULT_DOSStub_d7f2 {
  strings:
    $key_d7f2 = { 83 9a [2] f7 82 [2] b0 80 [2] f7 91 [2] b9 9d [2] b5 97 [2] a2 9c [2] b9 d2 [2] 84 }

  condition:
    any of them
}