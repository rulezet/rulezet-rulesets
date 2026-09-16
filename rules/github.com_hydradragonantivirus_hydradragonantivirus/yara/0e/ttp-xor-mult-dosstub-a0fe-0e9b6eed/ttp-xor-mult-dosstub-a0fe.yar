rule TTP_XOR_MULT_DOSStub_a0fe {
  strings:
    $key_a0fe = { f4 96 [2] 80 8e [2] c7 8c [2] 80 9d [2] ce 91 [2] c2 9b [2] d5 90 [2] ce de [2] f3 }

  condition:
    any of them
}