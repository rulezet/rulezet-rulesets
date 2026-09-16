rule TTP_XOR_MULT_DOSStub_972a {
  strings:
    $key_972a = { c3 42 [2] b7 5a [2] f0 58 [2] b7 49 [2] f9 45 [2] f5 4f [2] e2 44 [2] f9 0a [2] c4 }

  condition:
    any of them
}