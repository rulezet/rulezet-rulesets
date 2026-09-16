rule TTP_XOR_MULT_DOSStub_a428 {
  strings:
    $key_a428 = { f0 40 [2] 84 58 [2] c3 5a [2] 84 4b [2] ca 47 [2] c6 4d [2] d1 46 [2] ca 08 [2] f7 }

  condition:
    any of them
}