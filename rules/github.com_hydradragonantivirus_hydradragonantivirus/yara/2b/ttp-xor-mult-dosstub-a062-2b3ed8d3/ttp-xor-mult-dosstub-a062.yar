rule TTP_XOR_MULT_DOSStub_a062 {
  strings:
    $key_a062 = { f4 0a [2] 80 12 [2] c7 10 [2] 80 01 [2] ce 0d [2] c2 07 [2] d5 0c [2] ce 42 [2] f3 }

  condition:
    any of them
}