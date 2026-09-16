rule TTP_XOR_MULT_DOSStub_d64a {
  strings:
    $key_d64a = { 82 22 [2] f6 3a [2] b1 38 [2] f6 29 [2] b8 25 [2] b4 2f [2] a3 24 [2] b8 6a [2] 85 }

  condition:
    any of them
}