rule TTP_XOR_MULT_DOSStub_a02c {
  strings:
    $key_a02c = { f4 44 [2] 80 5c [2] c7 5e [2] 80 4f [2] ce 43 [2] c2 49 [2] d5 42 [2] ce 0c [2] f3 }

  condition:
    any of them
}