rule TTP_XOR_MULT_DOSStub_a03b {
  strings:
    $key_a03b = { f4 53 [2] 80 4b [2] c7 49 [2] 80 58 [2] ce 54 [2] c2 5e [2] d5 55 [2] ce 1b [2] f3 }

  condition:
    any of them
}