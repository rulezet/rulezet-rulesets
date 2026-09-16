rule TTP_XOR_MULT_DOSStub_a03a {
  strings:
    $key_a03a = { f4 52 [2] 80 4a [2] c7 48 [2] 80 59 [2] ce 55 [2] c2 5f [2] d5 54 [2] ce 1a [2] f3 }

  condition:
    any of them
}