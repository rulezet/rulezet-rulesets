rule TTP_XOR_MULT_DOSStub_d61a {
  strings:
    $key_d61a = { 82 72 [2] f6 6a [2] b1 68 [2] f6 79 [2] b8 75 [2] b4 7f [2] a3 74 [2] b8 3a [2] 85 }

  condition:
    any of them
}