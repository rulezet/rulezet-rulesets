rule TTP_XOR_MULT_DOSStub_914a {
  strings:
    $key_914a = { c5 22 [2] b1 3a [2] f6 38 [2] b1 29 [2] ff 25 [2] f3 2f [2] e4 24 [2] ff 6a [2] c2 }

  condition:
    any of them
}