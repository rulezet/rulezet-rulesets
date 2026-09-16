rule TTP_XOR_MULT_DOSStub_a421 {
  strings:
    $key_a421 = { f0 49 [2] 84 51 [2] c3 53 [2] 84 42 [2] ca 4e [2] c6 44 [2] d1 4f [2] ca 01 [2] f7 }

  condition:
    any of them
}