rule TTP_XOR_MULT_DOSStub_a026 {
  strings:
    $key_a026 = { f4 4e [2] 80 56 [2] c7 54 [2] 80 45 [2] ce 49 [2] c2 43 [2] d5 48 [2] ce 06 [2] f3 }

  condition:
    any of them
}