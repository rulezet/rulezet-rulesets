rule TTP_XOR_MULT_DOSStub_a028 {
  strings:
    $key_a028 = { f4 40 [2] 80 58 [2] c7 5a [2] 80 4b [2] ce 47 [2] c2 4d [2] d5 46 [2] ce 08 [2] f3 }

  condition:
    any of them
}