rule TTP_XOR_MULT_DOSStub_a01e {
  strings:
    $key_a01e = { f4 76 [2] 80 6e [2] c7 6c [2] 80 7d [2] ce 71 [2] c2 7b [2] d5 70 [2] ce 3e [2] f3 }

  condition:
    any of them
}