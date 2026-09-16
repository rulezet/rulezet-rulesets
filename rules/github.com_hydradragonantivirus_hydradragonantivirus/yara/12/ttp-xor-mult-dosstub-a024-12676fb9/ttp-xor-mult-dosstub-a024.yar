rule TTP_XOR_MULT_DOSStub_a024 {
  strings:
    $key_a024 = { f4 4c [2] 80 54 [2] c7 56 [2] 80 47 [2] ce 4b [2] c2 41 [2] d5 4a [2] ce 04 [2] f3 }

  condition:
    any of them
}