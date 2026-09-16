rule TTP_XOR_MULT_DOSStub_a429 {
  strings:
    $key_a429 = { f0 41 [2] 84 59 [2] c3 5b [2] 84 4a [2] ca 46 [2] c6 4c [2] d1 47 [2] ca 09 [2] f7 }

  condition:
    any of them
}