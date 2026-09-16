rule TTP_XOR_MULT_DOSStub_a04c {
  strings:
    $key_a04c = { f4 24 [2] 80 3c [2] c7 3e [2] 80 2f [2] ce 23 [2] c2 29 [2] d5 22 [2] ce 6c [2] f3 }

  condition:
    any of them
}