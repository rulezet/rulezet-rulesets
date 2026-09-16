rule TTP_XOR_MULT_DOSStub_a05f {
  strings:
    $key_a05f = { f4 37 [2] 80 2f [2] c7 2d [2] 80 3c [2] ce 30 [2] c2 3a [2] d5 31 [2] ce 7f [2] f3 }

  condition:
    any of them
}