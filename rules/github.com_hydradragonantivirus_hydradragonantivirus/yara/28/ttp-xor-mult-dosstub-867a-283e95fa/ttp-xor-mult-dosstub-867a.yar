rule TTP_XOR_MULT_DOSStub_867a {
  strings:
    $key_867a = { d2 12 [2] a6 0a [2] e1 08 [2] a6 19 [2] e8 15 [2] e4 1f [2] f3 14 [2] e8 5a [2] d5 }

  condition:
    any of them
}