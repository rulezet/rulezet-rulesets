rule TTP_XOR_MULT_DOSStub_d71a {
  strings:
    $key_d71a = { 83 72 [2] f7 6a [2] b0 68 [2] f7 79 [2] b9 75 [2] b5 7f [2] a2 74 [2] b9 3a [2] 84 }

  condition:
    any of them
}