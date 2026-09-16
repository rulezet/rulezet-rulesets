rule TTP_XOR_MULT_DOSStub_a015 {
  strings:
    $key_a015 = { f4 7d [2] 80 65 [2] c7 67 [2] 80 76 [2] ce 7a [2] c2 70 [2] d5 7b [2] ce 35 [2] f3 }

  condition:
    any of them
}