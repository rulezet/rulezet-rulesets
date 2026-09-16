rule TTP_XOR_MULT_DOSStub_a022 {
  strings:
    $key_a022 = { f4 4a [2] 80 52 [2] c7 50 [2] 80 41 [2] ce 4d [2] c2 47 [2] d5 4c [2] ce 02 [2] f3 }

  condition:
    any of them
}