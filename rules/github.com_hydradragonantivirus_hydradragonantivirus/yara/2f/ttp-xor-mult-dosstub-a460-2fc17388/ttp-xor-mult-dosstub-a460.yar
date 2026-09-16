rule TTP_XOR_MULT_DOSStub_a460 {
  strings:
    $key_a460 = { f0 08 [2] 84 10 [2] c3 12 [2] 84 03 [2] ca 0f [2] c6 05 [2] d1 0e [2] ca 40 [2] f7 }

  condition:
    any of them
}