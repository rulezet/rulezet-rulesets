rule TTP_XOR_MULT_DOSStub_a0f9 {
  strings:
    $key_a0f9 = { f4 91 [2] 80 89 [2] c7 8b [2] 80 9a [2] ce 96 [2] c2 9c [2] d5 97 [2] ce d9 [2] f3 }

  condition:
    any of them
}