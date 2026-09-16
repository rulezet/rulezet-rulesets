rule TTP_XOR_MULT_DOSStub_a013 {
  strings:
    $key_a013 = { f4 7b [2] 80 63 [2] c7 61 [2] 80 70 [2] ce 7c [2] c2 76 [2] d5 7d [2] ce 33 [2] f3 }

  condition:
    any of them
}