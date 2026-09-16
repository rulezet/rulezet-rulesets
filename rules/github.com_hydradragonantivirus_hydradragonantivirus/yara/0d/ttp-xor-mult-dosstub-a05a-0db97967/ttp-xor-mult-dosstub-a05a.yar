rule TTP_XOR_MULT_DOSStub_a05a {
  strings:
    $key_a05a = { f4 32 [2] 80 2a [2] c7 28 [2] 80 39 [2] ce 35 [2] c2 3f [2] d5 34 [2] ce 7a [2] f3 }

  condition:
    any of them
}