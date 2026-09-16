rule TTP_XOR_MULT_DOSStub_915a {
  strings:
    $key_915a = { c5 32 [2] b1 2a [2] f6 28 [2] b1 39 [2] ff 35 [2] f3 3f [2] e4 34 [2] ff 7a [2] c2 }

  condition:
    any of them
}