rule TTP_XOR_MULT_DOSStub_a029 {
  strings:
    $key_a029 = { f4 41 [2] 80 59 [2] c7 5b [2] 80 4a [2] ce 46 [2] c2 4c [2] d5 47 [2] ce 09 [2] f3 }

  condition:
    any of them
}