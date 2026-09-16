rule TTP_XOR_MULT_DOSStub_a01a {
  strings:
    $key_a01a = { f4 72 [2] 80 6a [2] c7 68 [2] 80 79 [2] ce 75 [2] c2 7f [2] d5 74 [2] ce 3a [2] f3 }

  condition:
    any of them
}