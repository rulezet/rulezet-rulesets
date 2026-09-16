rule TTP_XOR_MULT_DOSStub_a05b {
  strings:
    $key_a05b = { f4 33 [2] 80 2b [2] c7 29 [2] 80 38 [2] ce 34 [2] c2 3e [2] d5 35 [2] ce 7b [2] f3 }

  condition:
    any of them
}