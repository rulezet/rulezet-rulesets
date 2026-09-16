rule TTP_XOR_MULT_DOSStub_a03f {
  strings:
    $key_a03f = { f4 57 [2] 80 4f [2] c7 4d [2] 80 5c [2] ce 50 [2] c2 5a [2] d5 51 [2] ce 1f [2] f3 }

  condition:
    any of them
}