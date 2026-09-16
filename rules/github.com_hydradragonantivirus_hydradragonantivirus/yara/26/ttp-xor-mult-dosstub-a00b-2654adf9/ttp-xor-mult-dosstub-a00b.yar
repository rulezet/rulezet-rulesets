rule TTP_XOR_MULT_DOSStub_a00b {
  strings:
    $key_a00b = { f4 63 [2] 80 7b [2] c7 79 [2] 80 68 [2] ce 64 [2] c2 6e [2] d5 65 [2] ce 2b [2] f3 }

  condition:
    any of them
}