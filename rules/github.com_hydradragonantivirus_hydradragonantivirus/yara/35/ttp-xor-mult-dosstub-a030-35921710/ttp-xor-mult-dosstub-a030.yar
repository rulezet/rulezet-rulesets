rule TTP_XOR_MULT_DOSStub_a030 {
  strings:
    $key_a030 = { f4 58 [2] 80 40 [2] c7 42 [2] 80 53 [2] ce 5f [2] c2 55 [2] d5 5e [2] ce 10 [2] f3 }

  condition:
    any of them
}