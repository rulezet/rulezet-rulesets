rule TTP_XOR_MULT_DOSStub_a033 {
  strings:
    $key_a033 = { f4 5b [2] 80 43 [2] c7 41 [2] 80 50 [2] ce 5c [2] c2 56 [2] d5 5d [2] ce 13 [2] f3 }

  condition:
    any of them
}